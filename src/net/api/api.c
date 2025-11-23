#include "api.h"
#include "http_server.h"
#include "pico/time.h"
#include "pico/cyw43_arch.h"
#include "hardware/adc.h"
#include "lwip/ip4_addr.h"
#include "lwip/tcp.h"
#include "constants.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "serial.h"
#include "protocol.h"
#include "ap_manager.h"
#include "dhcpserver.h"
#include "crypto.h"
#include "wifi_ap.h"
#include "flash_config.h"
#include "cryptoauthlib.h"
#include "cpu_monitor.h"

// Forward-declared timer for deferred AP password rotation after claim
#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"
#include "semphr.h"

// Throttled API logging: set to 1 to enable verbose API logs to serial
#ifndef API_DEBUG
#define API_DEBUG 0
#endif
#if API_DEBUG
#define API_DBG(...) ////print_dbg(__VA_ARGS__)
#else
#define API_DBG(...) do { } while (0)
#endif

// State: has the device been claimed already?
static bool g_claimed = false;
// Cache the last generated password so we can optionally re-display or debug
static char g_last_psk[33] = "";             // 32 chars + NUL
static const uint32_t CLAIM_GRACE_MS = 2000; // TCP close + client reconnect time

// Bearer token authentication state
static char g_bearer_token[65] = ""; // 64 hex chars + NUL (256-bit token)
static bool g_bearer_token_generated = false;

// Generate a random WPA2 passphrase (length between 16 and 24) using get_rand_32()
static void generate_random_psk(char *out, size_t out_len) {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_len = sizeof(charset) - 1;
    if (out_len == 0) return;
    uint32_t seed = get_rand_32();
    size_t target = 16;
    if (target > out_len - 1) target = out_len - 1;
    for (size_t i = 0; i < target; i++) {
        // Mix hardware random each iteration for unpredictability
        uint32_t r = get_rand_32() ^ (seed + i * 0x9E3779B1u);
        out[i] = charset[r % charset_len];
    }
    out[target] = '\0';
}

// Generate a random bearer token (256-bit = 64 hex chars)
static void generate_bearer_token(char *out, size_t out_len) {
    static const char HEX[] = "0123456789abcdef";
    if (out_len < 65) return;

    for (int chunk = 0; chunk < 8; ++chunk) {
        uint32_t r = get_rand_32();
        for (int byte = 0; byte < 4; ++byte) {
            uint8_t b = (uint8_t)((r >> (byte * 8)) & 0xFF);
            int idx = chunk * 8 + byte * 2;
            out[idx] = HEX[(b >> 4) & 0x0F];
            out[idx + 1] = HEX[b & 0x0F];
        }
    }
    out[64] = '\0';
}

// Check if request has valid bearer token in Authorization header
// Returns true if token is valid, false otherwise
bool http_validate_bearer_token(const char *request) {
    if (!g_bearer_token_generated || g_bearer_token[0] == '\0') {
        // No token has been generated yet - reject all auth'd endpoints
        return false;
    }
    
    // Look for "Authorization: Bearer <token>" header
    const char *auth_header = strstr(request, "Authorization: Bearer ");
    if (!auth_header) {
        return false;
    }
    
    // Extract the token from the header
    const char *token_start = auth_header + strlen("Authorization: Bearer ");
    char request_token[65];
    
    // Read up to 64 chars or until we hit whitespace/newline
    int i = 0;
    while (i < 64 && token_start[i] != '\r' && token_start[i] != '\n' && token_start[i] != ' ' && token_start[i] != '\0') {
        request_token[i] = token_start[i];
        i++;
    }
    request_token[i] = '\0';
    
    // Compare tokens (constant-time to prevent timing attacks)
    int match = 1;
    for (int j = 0; j < 64; j++) {
        if (g_bearer_token[j] != request_token[j]) {
            match = 0;
        }
    }
    
    return match == 1;
}


// Claim handler: if not claimed, generate password, respond, then schedule AP restart.
static void claim_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    print_dbg("[API] claim_handler called (claimed=%d)\n", g_claimed ? 1 : 0);
    
    #ifdef DEBUG
    // In debug mode, allow re-claiming
    if (g_claimed) {
        print_dbg("[API] DEBUG: Allowing re-claim\n");
        g_claimed = false;
    }
    #endif

    if (g_claimed) {
        http_send_json(pcb, 409, "{\"error\":\"already_claimed\"}");
        return;
    }

    // Generate random WPA2 password
    generate_random_psk(g_last_psk, sizeof(g_last_psk));

    g_claimed = true;
    print_dbg("[API] About to send JSON response\n");

    char body[160];
    int n = snprintf(body, sizeof(body),
                     "{\"status\":\"ok\",\"ssid\":\"%s\",\"new_password\":\"%s\",\"message\":\"reboot_device\"}",
                     wifi_ap_get_config()->ssid, g_last_psk);
    (void)n;

    print_dbg("[API] Calling http_send_json\n");
    http_send_json(pcb, 200, body);

    print_dbg("[API] http_send_json returned\n");

    // Queue WiFi password write to background task (non-blocking)
    // This uses the same pattern as golden_hash writes for reliability
    if (crypto_queue_wifi_password_write(g_last_psk)) {
        print_dbg("[API] WiFi password queued for ATECC write\n");
    } else {
        print_dbg("[API] ERROR: Failed to queue WiFi password (task busy or not spawned)\n");
    }
}

// Generate bearer token handler - POST /api/auth/generate-token
// Returns a bearer token to be used for authenticating subsequent API requests
// Can only be called once per device startup (when token is not yet generated)
static void generate_token_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;

    if (g_bearer_token_generated) {
#ifdef DEBUG
        // DEBUG: Return the existing token instead of 409
        char body[200];
        int n = snprintf(body, sizeof(body),
            "{\"status\":\"ok\",\"bearer_token\":\"%s\",\"message\":\"Existing bearer token (DEBUG mode)\"}",
            g_bearer_token);
        (void)n;
        http_send_json(pcb, 200, body);
        return;
#else
        // PRODUCTION: Return 409 Conflict
        http_send_json(pcb, 409, "{\"error\":\"token_already_generated\",\"message\":\"Bearer token has already been issued for this device session\"}");
        return;
#endif
    }

    // Generate new bearer token (first request only)
    generate_bearer_token(g_bearer_token, sizeof(g_bearer_token));
    g_bearer_token_generated = true;

    API_DBG("[API] Bearer token generated: %s\n", g_bearer_token);

    // Return the token to the client
    char body[200];
    int n = snprintf(body, sizeof(body),
        "{\"status\":\"ok\",\"bearer_token\":\"%s\",\"message\":\"Store this token securely - it is your device password\"}",
        g_bearer_token);
    (void)n;

    http_send_json(pcb, 200, body);
}

// Lightweight ping endpoint for connectivity checks
static void ping_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    http_send_json(pcb, 200, "{\"message\":\"pong\"}");
}

// Lightweight health endpoint for quick connectivity checks
static void health_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    http_send_json(pcb, 200, "{\"ok\":true}");
}

/*
Status handler - returns system status information, including attecc status and uptime
*/
static void status_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] status_handler called\n");
    
    uint32_t ms = to_ms_since_boot(get_absolute_time());
    uint32_t s = ms / 1000;
    API_DBG("[API] got uptime: %u\n", (unsigned)s);
    
    API_DBG("[API] checking provisioning state\n");
    bool provisioned = (g_protocol_state.current_state != PROTOCOL_STATE_UNPROVISIONED);
    API_DBG("[API] provisioned: %d\n", provisioned);
    
    char body[256];
    API_DBG("[API] building JSON response\n");
    int n = snprintf(body, sizeof(body),
        "{\"provisioned\":%s, \"state\":\"0x%02X\", \"uptime_s\":%u, \"wifi_configured\":%s}",
        provisioned ? "true" : "false",
        g_protocol_state.current_state,
        (unsigned)s,
        g_claimed ? "true" : "false");
    API_DBG("[API] snprintf returned: %d, body: %s\n", n, body);
    (void)n;
    
    API_DBG("[API] sending response\n");
    http_send_json(pcb, 200, body);
    API_DBG("[API] response sent\n");
}

/**
 * Network info handler - returns AP SSID, client IPs, and MAC addresses
 * 
 * Requirements:
 * R-4.6.1: Display SSID and WPA2-PSK status
 * R-4.6.2: Display connected client IP addresses
 * R-4.6.3: Display MAC address + IP for each client
 * R-4.6.4: Refresh every 5 seconds (handled by client-side)
 */
static void network_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] network_handler called\n");
    
    // Get AP IP
    const ip4_addr_t *ap_ip = netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_AP]);
    const char *ap_ip_str = ap_ip ? ip4addr_ntoa(ap_ip) : "192.168.4.1";
    
    // Get DHCP server to query connected clients
    const dhcp_server_t *dhcp = get_dhcp_server();
    
    // Build JSON response with network info and connected clients
    // Maximum size: headers + 8 clients * (MAC 17 bytes + IP 15 bytes + JSON overhead)
    char body[768];
    int pos = 0;
    
    // Start JSON header
    pos += snprintf(body + pos, sizeof(body) - pos,
        "{\"ssid\":\"MASTR-Token\",\"security\":\"WPA2-PSK\",\"ap_ip\":\"%s\",\"clients\":[",
        ap_ip_str);
    
    // Add connected clients from DHCP leases
    #define DHCPS_MAX_IP 8
    #define DHCPS_BASE_IP 16
    
    int client_count = 0;
    for (int i = 0; i < DHCPS_MAX_IP; i++) {
        // Check if lease is active (expiry is non-zero and not expired)
        if (dhcp->lease[i].expiry != 0) {
            // Only add comma if not first client
            if (client_count > 0) {
                pos += snprintf(body + pos, sizeof(body) - pos, ",");
            }
            
            // Format MAC address from lease
            const uint8_t *mac = dhcp->lease[i].mac;
            uint8_t ip_octet = DHCPS_BASE_IP + i;
            
            pos += snprintf(body + pos, sizeof(body) - pos,
                "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"ip\":\"192.168.4.%u\"}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                ip_octet);
            
            client_count++;
            API_DBG("[API] client %d: %02X:%02X:%02X:%02X:%02X:%02X -> 192.168.4.%u\n",
                client_count, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip_octet);
        }
    }
    
    // Close JSON
    pos += snprintf(body + pos, sizeof(body) - pos, "]}");
    
    API_DBG("[API] network info: SSID=MASTR-Token, AP_IP=%s, clients=%d\n", ap_ip_str, client_count);
    http_send_json(pcb, 200, body);
    API_DBG("[API] network response sent\n");
}

/**
 * RAM info handler - returns RAM usage
 * 
 * Requirements:
 * R-4.5.2: Display RAM usage (total, used, free)
 */
static void ram_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] ram_handler called\n");
    
    // Get heap info
    size_t free_heap = xPortGetFreeHeapSize();
    size_t total_heap = configTOTAL_HEAP_SIZE;
    size_t used_heap = total_heap - free_heap;
    
    API_DBG("[API] heap - total: %u, used: %u, free: %u\n", 
        (unsigned)total_heap, (unsigned)used_heap, (unsigned)free_heap);
    
    // Build JSON response
    char body[256];
    int n = snprintf(body, sizeof(body),
        "{\"ram_total_kb\":%u,\"ram_used_kb\":%u,\"ram_free_kb\":%u,\"ram_used_percent\":%u}",
        (unsigned)(total_heap / 1024),
        (unsigned)(used_heap / 1024),
        (unsigned)(free_heap / 1024),
        (unsigned)((used_heap * 100) / total_heap));
    (void)n;
    
    API_DBG("[API] ram response: %s\n", body);
    http_send_json(pcb, 200, body);
    API_DBG("[API] ram response sent\n");
}

/**
 * Temperature handler - returns internal MCU temperature (°C)
 * 
 * Safe, low-overhead read using Pico SDK ADC driver. We enable the
 * internal sensor, discard the first sample, average a few readings,
 * then convert to degrees Celsius using the standard formula.
 */
static float read_internal_temperature_c(void) {
    // One-time ADC init (idempotent)
    static bool adc_ready = false;
    if (!adc_ready) {
        adc_init();
        adc_set_temp_sensor_enabled(true);
        adc_ready = true;
    }

    // Select internal temperature sensor channel (ADC input 4)
    adc_select_input(4);

    // Throw away the first reading after switching channels/sensor enable
    (void)adc_read();

    // Average several samples for stability
    const int SAMPLES = 8;
    uint32_t acc = 0;
    for (int i = 0; i < SAMPLES; i++) {
        acc += adc_read();
    }
    float raw = acc / (float)SAMPLES;

    // Convert raw 12-bit ADC reading to voltage (assumes 3.3V reference)
    const float VREF = 3.3f;
    float v = raw * VREF / 4095.0f;

    // Pico formula: 27°C at 0.706V, slope 1.721 mV/°C
    float temp_c = 27.0f - (v - 0.706f) / 0.001721f;
    return temp_c;
}

static void temperature_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] temperature_handler called\n");

    float t = read_internal_temperature_c();
    // Clamp to a sane range in case of transient anomalies
    if (t < -40.0f) t = -40.0f;
    if (t > 125.0f) t = 125.0f;

    char body[128];
    int n = snprintf(body, sizeof(body), "{\"temp_c\":%.1f}", (double)t);
    (void)n;
    API_DBG("[API] temperature: %.1f C\n", (double)t);
    http_send_json(pcb, 200, body);
}

/**
 * CPU utilization handler - returns CPU usage percentage
 * 
 * Requirements:
 * R-4.5.1: Display CPU utilization 
 * 
 * Formula: CPU% = (TotalDelta - IdleDelta) / TotalDelta * 100
 * 
 * Uses FreeRTOS idle hook to accurately measure idle vs busy time.
 * g_idleTicks is incremented by vApplicationIdleHook() each time idle task runs.
 */
static void cpu_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] cpu_handler called\n");
    uint32_t cpu_percent = cpu_get_percent();
    if (cpu_percent > 100U) cpu_percent = 100U;
    char body[128];
    int n = snprintf(body, sizeof(body), "{\"cpu_percent\":%u}", cpu_percent);
    (void)n;
    http_send_json(pcb, 200, body);
}

/**
 * Token info handler - returns token's public key for provisioning
 * GET /api/provision/token_info
 * Returns: {"token_pubkey":"<hex_string>"}
 */
static void token_info_handler(struct tcp_pcb *pcb, const char *request){
    (void)request;
    bool ready = false;
    const char *hex = NULL;
    ready = crypto_get_cached_token_pubkey_hex(&hex, &ready);
    API_DBG("[API] token_info_handler called (ready=%d failed=%d)\n", ready, crypto_token_pubkey_failed());
    if (!ready) {
        if (crypto_token_pubkey_failed()) {
            http_send_json(pcb, 500, "{\"error\":\"pubkey_prefetch_failed\"}");
        } else {
            http_send_json(pcb, 503, "{\"status\":\"initializing\",\"retry_ms\":100}");
        }
        return;
    }
    char body[180];
    int n = snprintf(body, sizeof(body), "{\"token_pubkey\":\"%s\",\"cached\":true}", hex);
    (void)n;
    http_send_json(pcb, 200, body);
}

/**
 * Set host public key handler (non-blocking)
 * POST /api/provision/host_pubkey
 * Expects: 64-byte hex string in request body (128 hex chars)
 * Returns: {"status":"accepted"} or {"error":"..."}
 */
static void set_host_pubkey_handler(struct tcp_pcb *pcb, const char *request) {
    // Find the request body (after double CRLF)
    const char *body_start = strstr(request, "\r\n\r\n");
    if (!body_start) {
        http_send_json(pcb, 400, "{\"error\":\"missing_body\"}");
        return;
    }
    body_start += 4; // Skip past "\r\n\r\n"
    
    // Trim whitespace and newlines from the end  
    const char *body_end = body_start + strlen(body_start);
    while (body_end > body_start && (body_end[-1] == '\r' || body_end[-1] == '\n' || body_end[-1] == ' ')) {
        body_end--;
    }
    
    // Create null-terminated string for the hex data
    size_t hex_len = body_end - body_start;
    
    if (hex_len != 128) {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":\"invalid_length\",\"expected\":128,\"got\":%zu}", hex_len);
        http_send_json(pcb, 400, error_msg);
        return;
    }
    
    // Validate hex format before proceeding
    for (size_t i = 0; i < 128; i++) {
        char c = body_start[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            http_send_json(pcb, 400, "{\"error\":\"invalid_hex_format\"}");
            return;
        }
    }
    
    // Create null-terminated string for the crypto function
    char hex_str[129];
    memcpy(hex_str, body_start, 128);
    hex_str[128] = '\0';

    // Use the new non-blocking crypto function
    bool write_ready, write_failed;
    bool accepted = crypto_request_host_pubkey_write(hex_str, &write_ready, &write_failed);
    
    if (!accepted) {
        http_send_json(pcb, 409, "{\"error\":\"write_pending\",\"retry_ms\":100}");
        return;
    }

    http_send_json(pcb, 202, "{\"status\":\"accepted\",\"message\":\"write_queued\"}");
}

/**
 * Get host public key handler (non-blocking)
 * GET /api/provision/host_pubkey/get
 * Returns: {"host_pubkey":"<hex_string>"} or {"status":"reading"} or {"error":"..."}
 */
static void get_host_pubkey_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    const char *hex_pubkey = NULL;
    bool ready = false;
    bool failed = false;
    
    crypto_get_cached_host_pubkey_hex(&hex_pubkey, &ready, &failed);
    
    if (failed) {
        http_send_json(pcb, 500, "{\"error\":\"read_failed\"}");
        return;
    }
    
    if (ready && hex_pubkey && hex_pubkey[0] != '\0') {
        // Return cached result
        char body[180];
        int n = snprintf(body, sizeof(body), "{\"host_pubkey\":\"%s\",\"cached\":true}", hex_pubkey);
        (void)n;
        http_send_json(pcb, 200, body);
        return;
    }
    
    // Still reading
    http_send_json(pcb, 503, "{\"status\":\"reading\",\"retry_ms\":100}");
}

/**
 * Get host public key write status handler (non-blocking)
 * GET /api/provision/host_pubkey/status
 * Returns: {"status":"ready|pending|failed"} 
 */
static void host_pubkey_status_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    bool write_ready = false;
    bool write_failed = false;
    
    crypto_get_host_pubkey_write_status(&write_ready, &write_failed);
    
    if (write_failed) {
        http_send_json(pcb, 200, "{\"status\":\"failed\"}");
    } else if (write_ready) {
        http_send_json(pcb, 200, "{\"status\":\"ready\"}");
    } else {
        http_send_json(pcb, 200, "{\"status\":\"pending\"}");
    }
}

/**
 * Set golden hash handler - POST /api/provision/golden_hash
 * Non-blocking version: validates input then triggers async crypto operation
 */
static void set_golden_hash_handler(struct tcp_pcb *pcb, const char *request) {
    // Extract hex data from request body
    const char *body_start = strstr(request, "\r\n\r\n");
    if (!body_start) {
        http_send_json(pcb, 400, "{\"error\":\"missing_body\"}");
        return;
    }
    body_start += 4;
    
    // Trim whitespace
    const char *body_end = body_start + strlen(body_start);
    while (body_end > body_start && (body_end[-1] == '\r' || body_end[-1] == '\n' || body_end[-1] == ' ')) {
        body_end--;
    }
    
    size_t hex_len = body_end - body_start;
    if (hex_len != 64) {
        http_send_json(pcb, 400, "{\"error\":\"invalid_length\"}");
        return;
    }
    
    // Validate hex format
    for (size_t i = 0; i < 64; i++) {
        char c = body_start[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            http_send_json(pcb, 400, "{\"error\":\"invalid_hex\"}");
            return;
        }
    }
    
    // Convert hex to bytes
    uint8_t golden_hash[32];
    for (int i = 0; i < 32; i++) {
        char hex_pair[3] = {body_start[i*2], body_start[i*2 + 1], '\0'};
        golden_hash[i] = (uint8_t)strtol(hex_pair, NULL, 16);
    }
    
    // Trigger async golden hash operation (non-blocking)
    bool queued = crypto_spawn_golden_hash_task_with_data(golden_hash);
    if (!queued) {
        http_send_json(pcb, 503, "{\"error\":\"task_busy\"}");
        return;
    }
    
    // Return immediate response - client should poll status
    http_send_json(pcb, 202, "{\"status\":\"accepted\",\"message\":\"golden_hash_operation_queued\"}");
}

/**
 * Get golden hash status handler - GET /api/provision/golden_hash/status
 * Returns the result of the most recent golden hash operation
 */
static void golden_hash_status_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request; // Unused parameter
    
    bool write_ready = false;
    bool write_failed = false;
    uint8_t golden_hash_result[32];
    
    crypto_get_golden_hash_write_status(&write_ready, &write_failed, golden_hash_result);
    
    if (write_ready) {
        // Convert result hash to hex
        char hex_response[65];
        for (int i = 0; i < 32; i++) {
            sprintf(&hex_response[i*2], "%02x", golden_hash_result[i]);
        }
        
        char response[150];
        snprintf(response, sizeof(response), "{\"status\":\"success\",\"golden_hash\":\"%s\"}", hex_response);
        http_send_json(pcb, 200, response);
    } else if (write_failed) {
        http_send_json(pcb, 200, "{\"status\":\"error\",\"error\":\"crypto_operation_failed\"}");
    } else {
        // Still processing or idle
        http_send_json(pcb, 200, "{\"status\":\"processing\"}");
    }
}

// Deferred reset task (runs after response is sent)
// Available in all builds for university module
static void reset_task(void *arg) {
    (void)arg;

    print_dbg("[API] Reset task: clearing ATECC608A provisioning data\n");
    protocol_unprovision();

    print_dbg("[API] Reset task: clearing WiFi password from ATECC608A\n");
    if (!crypto_clear_wifi_password()) {
        print_dbg("[API] ERROR: Failed to clear WiFi password\n");
    } else {
        print_dbg("[API] WiFi password cleared from ATECC successfully\n");
    }

    print_dbg("[API] Reset complete - device should be rebooted\n");

    // Task completes
    vTaskDelete(NULL);
}

// Timer callback for reset endpoint
// Runs in timer daemon context (safe to call xTaskCreate)
static void reset_timer_cb(TimerHandle_t timer) {
    print_dbg("[API] Reset timer fired, creating reset task\n");

    BaseType_t result = xTaskCreate(
        reset_task,
        "Reset",
        DEFAULT_STACK_SIZE,
        NULL,
        15,
        NULL
    );

    if (result != pdPASS) {
        print_dbg("[API] ERROR: Failed to create reset task from timer\n");
    }

    // Delete the one-shot timer
    xTimerDelete(timer, 0);
}

static void reset_api_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;

    print_dbg("[API] reset_api_handler called\n");

    // Clear claimed flag immediately (safe, no hardware access)
    g_claimed = false;

    // Send response immediately (before any hardware operations)
    print_dbg("[API] Sending reset response\n");
    char response[150];
    snprintf(response, sizeof(response), "{\"status\":\"success\",\"message\":\"reboot_device\"}");
    http_send_json(pcb, 200, response);

    print_dbg("[API] Response sent, creating timer\n");

    // Use a FreeRTOS timer instead of creating task directly
    // This avoids calling xTaskCreate() from lwIP context which causes deadlock
    TimerHandle_t timer = xTimerCreate(
        "ResetTimer",
        pdMS_TO_TICKS(2000),  // 2 second delay
        pdFALSE,              // One-shot timer
        NULL,
        reset_timer_cb        // Timer callback will create the task
    );

    if (timer != NULL) {
        if (xTimerStart(timer, 0) == pdPASS) {
            print_dbg("[API] Reset scheduled via timer\n");
        } else {
            print_dbg("[API] ERROR: Failed to start reset timer\n");
            xTimerDelete(timer, 0);
        }
    } else {
        print_dbg("[API] ERROR: Failed to create reset timer\n");
    }
}

#ifdef DEBUG
static void wifi_password_reset_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request; // Unused parameter

    print_dbg("[API] WiFi password reset requested (DEBUG mode)\n");

    if (!flash_clear_wifi_password()) {
        http_send_json(pcb, 500, "{\"error\":\"flash_clear_failed\"}");
        return;
    }

    g_claimed = false;

    http_send_json(pcb, 200,
        "{\"status\":\"password_cleared\",\"message\":\"reboot_to_open_ap\"}");
}
#endif

void api_register_routes(void) {
    bool password_set = wifi_ap_is_password_set();
    bool provisioned = (g_protocol_state.current_state != PROTOCOL_STATE_UNPROVISIONED);

    // Check if claimed (password pending write to flash/AP rotation)
    // g_claimed is set immediately when /api/claim is called, before flash write
    bool claimed_or_password_set = password_set || g_claimed;

    // Always expose health checks (no auth)
    http_register("/api/ping", ping_handler);
    http_register("/api/health", health_handler);

    // Always spawn WiFi password task (needed for claim endpoint in all states)
    crypto_spawn_wifi_password_task();

    // STATE 1: No password and not claimed → Only claim endpoint (NO bearer token)
    if (!claimed_or_password_set) {
        http_register("/api/claim", claim_handler);
        print_dbg("API: UNCLAIMED state - only /api/claim exposed (no auth)\n");
        return;
    }

    // STATE 2+: Password set → Expose bearer token generation
    http_register("/api/auth/generate-token", generate_token_handler);

    // Always expose claim with auth (for password rotation)
    http_register_auth("/api/claim", claim_handler, true);

    if (!provisioned) {
        // STATE 2: Password set, not provisioned → Provisioning endpoints
        http_register_auth("/api/provision/token_info", token_info_handler, true);
        http_register_auth("/api/provision/host_pubkey", set_host_pubkey_handler, true);
        http_register_auth("/api/provision/host_pubkey/get", get_host_pubkey_handler, true);
        http_register_auth("/api/provision/host_pubkey/status", host_pubkey_status_handler, true);
        http_register_auth("/api/provision/golden_hash", set_golden_hash_handler, true);
        http_register_auth("/api/provision/golden_hash/status", golden_hash_status_handler, true);

        print_dbg("API: CLAIMED state - provisioning endpoints exposed\n");

    } else {
        // STATE 3: Provisioned → Monitoring endpoints
        http_register_auth("/api/status", status_handler, true);
        http_register_auth("/api/network", network_handler, true);
        http_register_auth("/api/ram", ram_handler, true);
        http_register_auth("/api/temp", temperature_handler, true);
        http_register_auth("/api/cpu", cpu_handler, true);

        print_dbg("API: PROVISIONED state - monitoring endpoints exposed\n");
    }

    // Always spawn crypto tasks when password is set (both STATE 2 and STATE 3)
    // These are required for the serial protocol to function
    crypto_spawn_pubkey_prefetch();
    crypto_spawn_host_pubkey_task();
    crypto_spawn_golden_hash_task();

    // Expose token_info and reset in all builds (for university module)
    if (provisioned) {
        http_register_auth("/api/provision/token_info", token_info_handler, true);
        http_register_auth("/api/provision/reset", reset_api_handler, true);
    }

    #ifdef DEBUG
    // Debug mode: WiFi password reset endpoint
    http_register_auth("/api/wifi/reset", wifi_password_reset_handler, true);
    print_dbg("API: DEBUG mode - reset endpoints enabled\n");
    #endif
}
