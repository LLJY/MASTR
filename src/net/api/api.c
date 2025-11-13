#include "api/api.h"
#include "http/http_server.h"
#include "pico/time.h"
#include "pico/cyw43_arch.h"
#include "hardware/adc.h"
#include "lwip/ip4_addr.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "serial.h"
#include "protocol.h"
#include "ap/ap_manager.h"
#include "dhcp/dhcpserver.h"
#include "crypto.h"
#include "net/wifi_ap.h"
#include "cryptoauthlib.h"
#include "cpu_monitor.h"
#include "wifi_ap.h"

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
static char g_last_psk[33] = ""; // 32 chars + NUL

// Token pubkey caching/prefetch handled by crypt.c now

// One-shot timer callback to restart AP with new password
// Worker task to perform AP restart in a normal task context (not timer task)
static void ap_restart_task(void *arg) {
    (void)arg;
    // Small delay to ensure response left the device stack
    vTaskDelay(pdMS_TO_TICKS(50));
    if (g_last_psk[0] != '\0') {
        wifi_ap_rotate_password(g_last_psk);
    }
    vTaskDelete(NULL);
}

static void ap_rotate_timer_cb(TimerHandle_t xTimer) {
    (void)xTimer;
    // Create detached worker to do the heavy lifting (deinit/init may block)
    xTaskCreate(ap_restart_task, "ap_rst", 1024, NULL, tskIDLE_PRIORITY + 2, NULL);
}

// Generate a random WPA2 passphrase (length between 16 and 24) using get_rand_32()
static void generate_random_psk(char *out, size_t out_len) {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_len = sizeof(charset) - 1;
    if (out_len == 0) return;
    uint32_t seed = get_rand_32();
    size_t target = 16; // fixed length for now
    if (target > out_len - 1) target = out_len - 1;
    for (size_t i = 0; i < target; i++) {
        // Mix hardware random each iteration for unpredictability
        uint32_t r = get_rand_32() ^ (seed + i * 0x9E3779B1u);
        out[i] = charset[r % charset_len];
    }
    out[target] = '\0';
}

// Claim handler: if not claimed, generate password, respond, then schedule AP restart.
static void claim_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] claim_handler called\n");
    if (g_claimed) {
        http_send_json(pcb, 409, "{\"error\":\"already_claimed\"}");
        return;
    }
    generate_random_psk(g_last_psk, sizeof(g_last_psk));
    g_claimed = true;

    // Create one-shot timer to rotate AP after grace period so response is delivered first.
    const uint32_t GRACE_MS = 750; // client sees password then AP restarts
    TimerHandle_t t = xTimerCreate("ap_rot", pdMS_TO_TICKS(GRACE_MS), pdFALSE, NULL, ap_rotate_timer_cb);
    if (t) {
        xTimerStart(t, 0);
    } else {
        // Fallback: rotate immediately
        ap_rotate_timer_cb(NULL);
    }

    char body[160];
    int n = snprintf(body, sizeof(body),
                     "{\"status\":\"ok\",\"ssid\":\"%s\",\"new_password\":\"%s\",\"reconnect_in_ms\":%u}",
                     wifi_ap_get_config()->ssid, g_last_psk, GRACE_MS);
    (void)n;
    http_send_json(pcb, 200, body);
}

// CPU utilization tracking handled inside cpu_monitor (runtime-only)

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
    bool provisioned = (g_protocol_state.current_state == 0x40);
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
    ////print_dbg("API: set_host_pubkey_handler called (non-blocking)\n");
    
    // Find the request body (after double CRLF)
    const char *body_start = strstr(request, "\r\n\r\n");
    if (!body_start) {
        ////print_dbg("API: missing request body\n");
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
    ////print_dbg("API: received hex data length: %zu\n", hex_len);
    
    if (hex_len != 128) {
        ////print_dbg("API: invalid hex length, expected 128, got %zu\n", hex_len);
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":\"invalid_length\",\"expected\":128,\"got\":%zu}", hex_len);
        http_send_json(pcb, 400, error_msg);
        return;
    }
    
    // Validate hex format before proceeding
    for (size_t i = 0; i < 128; i++) {
        char c = body_start[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            ////print_dbg("API: invalid hex character at position %zu: '%c'\n", i, c);
            http_send_json(pcb, 400, "{\"error\":\"invalid_hex_format\"}");
            return;
        }
    }
    
    ////print_dbg("API: hex validation passed, creating null-terminated string\n");
    
    // Create null-terminated string for the crypto function
    char hex_str[129];
    memcpy(hex_str, body_start, 128);
    hex_str[128] = '\0';
    
    ////print_dbg("API: requesting non-blocking host pubkey write\n");
    
    // Use the new non-blocking crypto function
    bool write_ready, write_failed;
    bool accepted = crypto_request_host_pubkey_write(hex_str, &write_ready, &write_failed);
    
    if (!accepted) {
        ////print_dbg("API: Host pubkey write request rejected (already pending)\n");
        http_send_json(pcb, 409, "{\"error\":\"write_pending\",\"retry_ms\":100}");
        return;
    }
    
    ////print_dbg("API: Host pubkey write request accepted\n");
    http_send_json(pcb, 202, "{\"status\":\"accepted\",\"message\":\"write_queued\"}");
}

/**
 * Get host public key handler (non-blocking)
 * GET /api/provision/host_pubkey/get
 * Returns: {"host_pubkey":"<hex_string>"} or {"status":"reading"} or {"error":"..."}
 */
static void get_host_pubkey_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    ////print_dbg("API: get_host_pubkey_handler called (non-blocking)\n");
    
    const char *hex_pubkey = NULL;
    bool ready = false;
    bool failed = false;
    
    crypto_get_cached_host_pubkey_hex(&hex_pubkey, &ready, &failed);
    
    if (failed) {
        ////print_dbg("API: Host pubkey read failed\n");
        http_send_json(pcb, 500, "{\"error\":\"read_failed\"}");
        return;
    }
    
    if (ready && hex_pubkey && hex_pubkey[0] != '\0') {
        // Return cached result
        char body[180];
        int n = snprintf(body, sizeof(body), "{\"host_pubkey\":\"%s\",\"cached\":true}", hex_pubkey);
        (void)n;
        ////print_dbg("API: Returning cached host pubkey\n");
        http_send_json(pcb, 200, body);
        return;
    }
    
    // Still reading
    ////print_dbg("API: Host pubkey not ready yet\n");
    http_send_json(pcb, 503, "{\"status\":\"reading\",\"retry_ms\":100}");
}

/**
 * Get host public key write status handler (non-blocking)
 * GET /api/provision/host_pubkey/status
 * Returns: {"status":"ready|pending|failed"} 
 */
static void host_pubkey_status_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    ////print_dbg("API: host_pubkey_status_handler called\n");
    
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

void api_register_routes(void) {
    http_register("/api/ping", ping_handler);
    http_register("/api/health", health_handler);
    http_register("/api/status", status_handler);
    http_register("/api/network", network_handler);
    http_register("/api/ram", ram_handler);
    http_register("/api/temp", temperature_handler);
    http_register("/api/cpu", cpu_handler);
    http_register("/api/claim", claim_handler);
    
    print_dbg("protocol state is currently at: 0x%02X", g_protocol_state.current_state);
    if(g_protocol_state.current_state == PROTOCOL_STATE_UNPROVISIONED){
        // Provisioning token public key endpoint (single canonical path)
        http_register("/api/provision/token_info", token_info_handler);
        // Provisioning host public key endpoints (non-blocking versions)
        http_register("/api/provision/host_pubkey", set_host_pubkey_handler);  // POST to set
        http_register("/api/provision/host_pubkey/get", get_host_pubkey_handler);  // GET to read
        http_register("/api/provision/host_pubkey/status", host_pubkey_status_handler);  // GET write status
        // Provisioning golden hash endpoints (non-blocking versions)
        http_register("/api/provision/golden_hash", set_golden_hash_handler);  // POST to set
        http_register("/api/provision/golden_hash/status", golden_hash_status_handler);  // GET status
    }else{
        print_dbg("protocol has already been provisioned, skipping provisioning endpoints...");
    }
    // Ask crypt layer to spawn prefetch task (low priority)
    crypto_spawn_pubkey_prefetch();
    
    // Start background task for host pubkey operations (non-blocking)
    crypto_spawn_host_pubkey_task();
    
    // Start background task for golden hash operations (non-blocking)
    crypto_spawn_golden_hash_task();
    
    ////print_dbg("API routes registered\n");
}
