#include "api/api.h"
#include "http/http_server.h"
#include "pico/time.h"
#include "pico/cyw43_arch.h"
#include "hardware/adc.h"
#include "lwip/ip4_addr.h"
#include <stdio.h>
#include <string.h>
#include "serial.h"
#include "protocol.h"

static void ping_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    http_send_json(pcb, 200, "{\"message\":\"pong\"}");
}

static void info_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    uint32_t ms = to_ms_since_boot(get_absolute_time());
    uint32_t s = ms / 1000;

    // Get AP IP if available
    const ip4_addr_t *ap_ip = netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_AP]);
    const char *ipstr = ap_ip ? ip4addr_ntoa(ap_ip) : "0.0.0.0";

    // Return a JSON object with several fields. Some fields (cpu, free_heap)
    // are placeholders for now and set to null; you can fill them in later.
    char body[256];
    // Read die temperature via RP2040 ADC temp sensor. Use a small sample
    // average to reduce noise. We avoid relying on printf float support by
    // formatting temperature as M.N (one decimal) using integer math.
    adc_init();
    adc_set_temp_sensor_enabled(true);
    adc_select_input(4);
    const int samples = 8;
    uint32_t sum = 0;
    for (int i = 0; i < samples; ++i) {
        sum += adc_read();
        sleep_ms(2);
    }
    float raw = (float)sum / samples;
    const float conversion = 3.3f / (1 << 12); // ADC is 12-bit
    float v = raw * conversion;
    float temp_c = 27.0f - (v - 0.706f) / 0.001721f;
    adc_set_temp_sensor_enabled(false);

    // Convert to tenths (one decimal) as integers to avoid float printf
    int temp_tenths = (int)(temp_c * 10.0f + (temp_c >= 0 ? 0.5f : -0.5f));
    int temp_whole = temp_tenths / 10;
    int temp_frac = abs(temp_tenths % 10);

    int n = snprintf(body, sizeof(body),
        "{\"uptime_s\":%u, \"ip\":\"%s\", \"cpu\":null, \"free_heap\":null, \"temp_c\":%d.%d}",
        (unsigned)s, ipstr, temp_whole, temp_frac);
    (void)n;
    http_send_json(pcb, 200, body);
}

static void status_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    print_dbg("[API] status_handler called\n");
    
    uint32_t ms = to_ms_since_boot(get_absolute_time());
    uint32_t s = ms / 1000;
    print_dbg("[API] got uptime: %u\n", (unsigned)s);
    
    print_dbg("[API] checking provisioning state\n");
    bool provisioned = (protocol_state.current_state == 0x40);
    print_dbg("[API] provisioned: %d\n", provisioned);
    
    char body[256];
    print_dbg("[API] building JSON response\n");
    int n = snprintf(body, sizeof(body),
        "{\"provisioned\":%s, \"state\":\"0x%02X\", \"uptime_s\":%u}",
        provisioned ? "true" : "false",
        protocol_state.current_state,
        (unsigned)s);
    print_dbg("[API] snprintf returned: %d, body: %s\n", n, body);
    (void)n;
    
    print_dbg("[API] sending response\n");
    http_send_json(pcb, 200, body);
    print_dbg("[API] response sent\n");
}

void api_register_routes(void) {
    http_register("/api/ping", ping_handler);
    http_register("/api/info", info_handler);
    http_register("/api/status", status_handler);
    print_dbg("API routes registered\n");
}
