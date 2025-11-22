#include "api.h"
#include "http_server.h"
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
#include "ap_manager.h"
#include "dhcpserver.h"
#include "crypto.h"
#include "wifi_ap.h"
#include "cryptoauthlib.h"
#include "cpu_monitor.h"
#include "wifi_ap.h"

#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"
#include "semphr.h"

#ifdef DEBUG
#define API_DBG(...) print_dbg(__VA_ARGS__)
#else
#define API_DBG(...) do { } while (0)
#endif

static bool g_claimed = false;
static char g_last_psk[33] = "";

static char g_bearer_token[65] = "";
static bool g_bearer_token_generated = false;

/*******************************************************************************
 * @brief Restart the AP with the latest password after claim.
 * @param arg Unused task argument.
 * @return void
 ******************************************************************************/
static void ap_restart_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(50));
    if (g_last_psk[0] != '\0') {
        wifi_ap_rotate_password(g_last_psk);
    }
    vTaskDelete(NULL);
}

/*******************************************************************************
 * @brief Timer callback that schedules AP rotation work.
 * @param xTimer Unused timer handle.
 * @return void
 ******************************************************************************/
static void ap_rotate_timer_cb(TimerHandle_t xTimer) {
    (void)xTimer;
    xTaskCreate(ap_restart_task, "ap_rst", 1024, NULL, tskIDLE_PRIORITY + 2, NULL);
}

/*******************************************************************************
 * @brief Generate a random WPA2 passphrase.
 * @param out Destination buffer for the passphrase.
 * @param out_len Size of the destination buffer.
 * @return void
 ******************************************************************************/
static void generate_random_psk(char *out, size_t out_len) {
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_len = sizeof(charset) - 1;
    if (out_len == 0) return;
    uint32_t seed = get_rand_32();
    size_t target = 16;
    if (target > out_len - 1) target = out_len - 1;
    for (size_t i = 0; i < target; i++) {
        uint32_t r = get_rand_32() ^ (seed + i * 0x9E3779B1u);
        out[i] = charset[r % charset_len];
    }
    out[target] = '\0';
}

/*******************************************************************************
 * @brief Generate a random 256-bit bearer token as hex.
 * @param out Destination buffer for the hex token.
 * @param out_len Size of the destination buffer.
 * @return void
 ******************************************************************************/
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

/*******************************************************************************
 * @brief Validate bearer token presence and match.
 * @param request Raw HTTP request buffer.
 * @return true if the bearer token matches the generated token; false otherwise.
 ******************************************************************************/
bool http_validate_bearer_token(const char *request) {
    if (!g_bearer_token_generated || g_bearer_token[0] == '\0') {
        return false;
    }
    
    const char *auth_header = strstr(request, "Authorization: Bearer ");
    if (!auth_header) {
        return false;
    }
    
    const char *token_start = auth_header + strlen("Authorization: Bearer ");
    char request_token[65];
    
    int i = 0;
    while (i < 64 && token_start[i] != '\r' && token_start[i] != '\n' && token_start[i] != ' ' && token_start[i] != '\0') {
        request_token[i] = token_start[i];
        i++;
    }
    request_token[i] = '\0';
    
    int match = 1;
    for (int j = 0; j < 64; j++) {
        if (g_bearer_token[j] != request_token[j]) {
            match = 0;
        }
    }
    
    return match == 1;
}


/*******************************************************************************
 * @brief Handle initial claim flow and rotate the AP password.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void claim_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] claim_handler called\n");
    if (g_claimed) {
        http_send_json(pcb, 409, "{\"error\":\"already_claimed\"}");
        return;
    }
    generate_random_psk(g_last_psk, sizeof(g_last_psk));
    g_claimed = true;

    const uint32_t GRACE_MS = 750;
    TimerHandle_t t = xTimerCreate("ap_rot", pdMS_TO_TICKS(GRACE_MS), pdFALSE, NULL, ap_rotate_timer_cb);
    if (t) {
        xTimerStart(t, 0);
    } else {
        ap_rotate_timer_cb(NULL);
    }

    char body[160];
    int n = snprintf(body, sizeof(body),
                     "{\"status\":\"ok\",\"ssid\":\"%s\",\"new_password\":\"%s\",\"reconnect_in_ms\":%u}",
                     wifi_ap_get_config()->ssid, g_last_psk, GRACE_MS);
    (void)n;
    http_send_json(pcb, 200, body);
}

/*******************************************************************************
 * @brief Issue a bearer token for authenticating future API requests.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void generate_token_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] generate_token_handler called\n");
    
#ifndef DEBUG
    if (g_bearer_token_generated) {
        http_send_json(pcb, 409, "{\"error\":\"token_already_generated\",\"message\":\"Bearer token has already been issued for this device session\"}");
        return;
    }
#else
    if (g_bearer_token_generated) {
        API_DBG("[API] DEBUG build: regenerating bearer token for testing\n");
    }
#endif
    
    generate_bearer_token(g_bearer_token, sizeof(g_bearer_token));
    g_bearer_token_generated = true;
    
    API_DBG("[API] Bearer token generated: %s\n", g_bearer_token);
    
    char body[200];
    int n = snprintf(body, sizeof(body),
        "{\"status\":\"ok\",\"bearer_token\":\"%s\",\"message\":\"Store this token securely - it is your device password\"}",
        g_bearer_token);
    (void)n;
    
    http_send_json(pcb, 200, body);
}

/*******************************************************************************
 * @brief Respond to ping health checks.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void ping_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    http_send_json(pcb, 200, "{\"message\":\"pong\"}");
}

/*******************************************************************************
 * @brief Lightweight health endpoint for quick connectivity checks.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void health_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    http_send_json(pcb, 200, "{\"ok\":true}");
}

/*******************************************************************************
 * @brief Return system status including provisioning state and uptime.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
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

/*******************************************************************************
 * @brief Return AP network info including SSID and connected clients.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void network_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] network_handler called\n");
    
    const ip4_addr_t *ap_ip = netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_AP]);
    const char *ap_ip_str = ap_ip ? ip4addr_ntoa(ap_ip) : "192.168.4.1";
    
    const dhcp_server_t *dhcp = get_dhcp_server();
    
    char body[768];
    int pos = 0;
    
    pos += snprintf(body + pos, sizeof(body) - pos,
        "{\"ssid\":\"MASTR-Token\",\"security\":\"WPA2-PSK\",\"ap_ip\":\"%s\",\"clients\":[",
        ap_ip_str);
    
    #define DHCPS_MAX_IP 8
    #define DHCPS_BASE_IP 16
    
    int client_count = 0;
    for (int i = 0; i < DHCPS_MAX_IP; i++) {
        if (dhcp->lease[i].expiry != 0) {
            if (client_count > 0) {
                pos += snprintf(body + pos, sizeof(body) - pos, ",");
            }
            
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
    
    pos += snprintf(body + pos, sizeof(body) - pos, "]}");
    
    API_DBG("[API] network info: SSID=MASTR-Token, AP_IP=%s, clients=%d\n", ap_ip_str, client_count);
    http_send_json(pcb, 200, body);
    API_DBG("[API] network response sent\n");
}

/*******************************************************************************
 * @brief Report RAM usage totals and percentages.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void ram_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] ram_handler called\n");
    
    size_t free_heap = xPortGetFreeHeapSize();
    size_t total_heap = configTOTAL_HEAP_SIZE;
    size_t used_heap = total_heap - free_heap;
    
    API_DBG("[API] heap - total: %u, used: %u, free: %u\n", 
        (unsigned)total_heap, (unsigned)used_heap, (unsigned)free_heap);
    
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

/*******************************************************************************
 * @brief Read the internal MCU temperature in Celsius.
 * @return Measured temperature in degrees Celsius.
 ******************************************************************************/
static float read_internal_temperature_c(void) {
    static bool adc_ready = false;
    if (!adc_ready) {
        adc_init();
        adc_set_temp_sensor_enabled(true);
        adc_ready = true;
    }

    adc_select_input(4);

    (void)adc_read();

    const int SAMPLES = 8;
    uint32_t acc = 0;
    for (int i = 0; i < SAMPLES; i++) {
        acc += adc_read();
    }
    float raw = acc / (float)SAMPLES;

    const float VREF = 3.3f;
    float v = raw * VREF / 4095.0f;

    float temp_c = 27.0f - (v - 0.706f) / 0.001721f;
    return temp_c;
}

/*******************************************************************************
 * @brief Serve current MCU temperature.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void temperature_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    API_DBG("[API] temperature_handler called\n");

    float t = read_internal_temperature_c();
    if (t < -40.0f) t = -40.0f;
    if (t > 125.0f) t = 125.0f;

    char body[128];
    int n = snprintf(body, sizeof(body), "{\"temp_c\":%.1f}", (double)t);
    (void)n;
    API_DBG("[API] temperature: %.1f C\n", (double)t);
    http_send_json(pcb, 200, body);
}

/*******************************************************************************
 * @brief Serve current CPU utilization percentage.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
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

/*******************************************************************************
 * @brief Serve the token public key for provisioning.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
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

/*******************************************************************************
 * @brief Accept and validate host public key submission.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void set_host_pubkey_handler(struct tcp_pcb *pcb, const char *request) {
    const char *body_start = strstr(request, "\r\n\r\n");
    if (!body_start) {
        http_send_json(pcb, 400, "{\"error\":\"missing_body\"}");
        return;
    }
    body_start += 4;
    
    const char *body_end = body_start + strlen(body_start);
    while (body_end > body_start && (body_end[-1] == '\r' || body_end[-1] == '\n' || body_end[-1] == ' ')) {
        body_end--;
    }
    
    size_t hex_len = body_end - body_start;
    
    if (hex_len != 128) {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":\"invalid_length\",\"expected\":128,\"got\":%zu}", hex_len);
        http_send_json(pcb, 400, error_msg);
        return;
    }
    
    for (size_t i = 0; i < 128; i++) {
        char c = body_start[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            http_send_json(pcb, 400, "{\"error\":\"invalid_hex_format\"}");
            return;
        }
    }
    
    char hex_str[129];
    memcpy(hex_str, body_start, 128);
    hex_str[128] = '\0';
    
    bool write_ready, write_failed;
    bool accepted = crypto_request_host_pubkey_write(hex_str, &write_ready, &write_failed);
    
    if (!accepted) {
        http_send_json(pcb, 409, "{\"error\":\"write_pending\",\"retry_ms\":100}");
        return;
    }
    
    http_send_json(pcb, 202, "{\"status\":\"accepted\",\"message\":\"write_queued\"}");
}

/*******************************************************************************
 * @brief Return the host public key if available.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
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
        char body[180];
        int n = snprintf(body, sizeof(body), "{\"host_pubkey\":\"%s\",\"cached\":true}", hex_pubkey);
        (void)n;
        http_send_json(pcb, 200, body);
        return;
    }
    
    http_send_json(pcb, 503, "{\"status\":\"reading\",\"retry_ms\":100}");
}

/*******************************************************************************
 * @brief Report status of the host public key write operation.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
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

/*******************************************************************************
 * @brief Accept a golden hash value and trigger async processing.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void set_golden_hash_handler(struct tcp_pcb *pcb, const char *request) {
    const char *body_start = strstr(request, "\r\n\r\n");
    if (!body_start) {
        http_send_json(pcb, 400, "{\"error\":\"missing_body\"}");
        return;
    }
    body_start += 4;
    
    const char *body_end = body_start + strlen(body_start);
    while (body_end > body_start && (body_end[-1] == '\r' || body_end[-1] == '\n' || body_end[-1] == ' ')) {
        body_end--;
    }
    
    size_t hex_len = body_end - body_start;
    if (hex_len != 64) {
        http_send_json(pcb, 400, "{\"error\":\"invalid_length\"}");
        return;
    }
    
    for (size_t i = 0; i < 64; i++) {
        char c = body_start[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            http_send_json(pcb, 400, "{\"error\":\"invalid_hex\"}");
            return;
        }
    }
    
    uint8_t golden_hash[32];
    for (int i = 0; i < 32; i++) {
        char hex_pair[3] = {body_start[i*2], body_start[i*2 + 1], '\0'};
        golden_hash[i] = (uint8_t)strtol(hex_pair, NULL, 16);
    }
    
    bool queued = crypto_spawn_golden_hash_task_with_data(golden_hash);
    if (!queued) {
        http_send_json(pcb, 503, "{\"error\":\"task_busy\"}");
        return;
    }
    
    http_send_json(pcb, 202, "{\"status\":\"accepted\",\"message\":\"golden_hash_operation_queued\"}");
}

/*******************************************************************************
 * @brief Report the status of the golden hash operation.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void golden_hash_status_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    
    bool write_ready = false;
    bool write_failed = false;
    uint8_t golden_hash_result[32];
    
    crypto_get_golden_hash_write_status(&write_ready, &write_failed, golden_hash_result);
    
    if (write_ready) {
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
        http_send_json(pcb, 200, "{\"status\":\"processing\"}");
    }
}

#ifdef DEBUG
/*******************************************************************************
 * @brief Debug endpoint to reset provisioning state.
 * @param pcb TCP control block for the client connection.
 * @param request Incoming HTTP request.
 * @return void
 ******************************************************************************/
static void reset_api_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
        
    protocol_unprovision();
    
    char response[150];
    snprintf(response, sizeof(response), "{\"status\":\"success\",");
    http_send_json(pcb, 200, response);
}
#endif

/*******************************************************************************
 * @brief Register all API routes with the HTTP server.
 * @return void
 ******************************************************************************/
void api_register_routes(void) {
    http_register("/api/ping", ping_handler);
    http_register("/api/health", health_handler);
    http_register("/api/auth/generate-token", generate_token_handler);
    
    http_register_auth("/api/status", status_handler, true);
    http_register_auth("/api/network", network_handler, true);
    http_register_auth("/api/ram", ram_handler, true);
    http_register_auth("/api/temp", temperature_handler, true);
    http_register_auth("/api/cpu", cpu_handler, true);
    http_register_auth("/api/claim", claim_handler, true);
    
    print_dbg("protocol state is currently at: 0x%02X", g_protocol_state.current_state);
    if(g_protocol_state.current_state == PROTOCOL_STATE_UNPROVISIONED){
        http_register_auth("/api/provision/token_info", token_info_handler, true);
        http_register_auth("/api/provision/host_pubkey", set_host_pubkey_handler, true);
        http_register_auth("/api/provision/host_pubkey/get", get_host_pubkey_handler, true);
        http_register_auth("/api/provision/host_pubkey/status", host_pubkey_status_handler, true);
        http_register_auth("/api/provision/golden_hash", set_golden_hash_handler, true);
        http_register_auth("/api/provision/golden_hash/status", golden_hash_status_handler, true);
    }else{
        print_dbg("protocol has already been provisioned, skipping provisioning endpoints...");
    }
    #ifdef DEBUG
    if(g_protocol_state.current_state != PROTOCOL_STATE_UNPROVISIONED){
        http_register_auth("/api/provision/token_info", token_info_handler, true);
        http_register_auth("/api/provision/host_pubkey", set_host_pubkey_handler, true);
        http_register_auth("/api/provision/host_pubkey/get", get_host_pubkey_handler, true);
        http_register_auth("/api/provision/host_pubkey/status", host_pubkey_status_handler, true);
        http_register_auth("/api/provision/golden_hash", set_golden_hash_handler, true);
        http_register_auth("/api/provision/golden_hash/status", golden_hash_status_handler, true);
        http_register_auth("/api/provision/reset", reset_api_handler, true); 
    }
    #endif
    crypto_spawn_pubkey_prefetch();
    
    crypto_spawn_host_pubkey_task();
    
    crypto_spawn_golden_hash_task();
}
