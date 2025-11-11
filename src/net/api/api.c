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
#include "crypt.h"
#include "net/wifi_ap.h"
#include "cryptoauthlib.h"
#include "cpu_monitor.h"

// CPU utilization tracking - hybrid approach: runtime stats primary, tick fallback
static uint32_t cpu_last_total_ticks = 0;
static uint32_t cpu_last_idle_ticks = 0;
static uint32_t cpu_accum_total = 0; // tick-based accumulation window (smoothing)
static uint32_t cpu_accum_idle  = 0;
static uint32_t cpu_last_report = 0; // last reported percent

// External idle tick counter from cpu_monitor.c
extern volatile uint32_t g_idleTicks;

static void ping_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    http_send_json(pcb, 200, "{\"message\":\"pong\"}");
}

/*
Status handler - returns system status information, including attecc status and uptime
*/
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
    print_dbg("[API] network_handler called\n");
    
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
            print_dbg("[API] client %d: %02X:%02X:%02X:%02X:%02X:%02X -> 192.168.4.%u\n",
                client_count, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip_octet);
        }
    }
    
    // Close JSON
    pos += snprintf(body + pos, sizeof(body) - pos, "]}");
    
    print_dbg("[API] network info: SSID=MASTR-Token, AP_IP=%s, clients=%d\n", ap_ip_str, client_count);
    http_send_json(pcb, 200, body);
    print_dbg("[API] network response sent\n");
}

/**
 * RAM info handler - returns RAM usage
 * 
 * Requirements:
 * R-4.5.2: Display RAM usage (total, used, free)
 */
static void ram_handler(struct tcp_pcb *pcb, const char *request) {
    (void)request;
    print_dbg("[API] ram_handler called\n");
    
    // Get heap info
    size_t free_heap = xPortGetFreeHeapSize();
    size_t total_heap = configTOTAL_HEAP_SIZE;
    size_t used_heap = total_heap - free_heap;
    
    print_dbg("[API] heap - total: %u, used: %u, free: %u\n", 
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
    
    print_dbg("[API] ram response: %s\n", body);
    http_send_json(pcb, 200, body);
    print_dbg("[API] ram response sent\n");
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
    print_dbg("[API] cpu_handler called\n");

    // Runtime stats percent (primary)
    uint32_t rt_cpu_percent = cpu_get_percent();

    // Tick snapshots for fallback and smoothing
    uint32_t current_total_ticks = xTaskGetTickCount();
    uint32_t current_idle_ticks  = g_idleTicks;

    uint32_t cpu_percent = cpu_last_report;

    if (cpu_last_total_ticks > 0) {
        uint32_t total_delta = current_total_ticks - cpu_last_total_ticks;
        uint32_t idle_delta  = current_idle_ticks  - cpu_last_idle_ticks;

        if (idle_delta <= total_delta) {
            cpu_accum_total += total_delta;
            cpu_accum_idle  += idle_delta;
        }

        // Build a small tick window (~50ms) for stability
        const uint32_t MIN_TICK_WINDOW = 50; // at 1kHz tick
        if (cpu_accum_total >= MIN_TICK_WINDOW) {
            uint32_t busy_ticks_accum = (cpu_accum_total > cpu_accum_idle) ? (cpu_accum_total - cpu_accum_idle) : 0;
            uint32_t tick_cpu_accum = (cpu_accum_total > 0) ? (busy_ticks_accum * 100U + (cpu_accum_total/2U)) / cpu_accum_total : 0; // rounded

            // Choose runtime stats if valid; else tick
            uint32_t chosen = (rt_cpu_percent <= 100U) ? rt_cpu_percent : tick_cpu_accum;
            if (chosen == 0 && busy_ticks_accum > 0) {
                chosen = 1; // floor to 1% if any busy ticks observed
            }
            cpu_percent = chosen;
            cpu_last_report = cpu_percent;

            cpu_accum_total = 0;
            cpu_accum_idle  = 0;
            print_dbg("[API] CPU(win)=%u%% (rt=%u%%, tick_accum=%u%%, win_total=%u, win_idle=%u)\n",
                      cpu_percent, rt_cpu_percent, tick_cpu_accum, cpu_accum_total, cpu_accum_idle);
        } else {
            // Pending window: keep last report but show latest rt percent in logs
            print_dbg("[API] CPU(pending) last=%u%% (rt=%u%%, accum_total=%u)\n",
                      cpu_last_report, rt_cpu_percent, cpu_accum_total);
        }
    } else {
        print_dbg("[API] CPU: initializing\n");
        cpu_percent = (rt_cpu_percent <= 100U) ? rt_cpu_percent : 0;
        cpu_last_report = cpu_percent;
    }

    // Store for next call
    cpu_last_total_ticks = current_total_ticks;
    cpu_last_idle_ticks  = current_idle_ticks;

    if (cpu_percent > 100U) cpu_percent = 100U;

    char body[128];
    int n = snprintf(body, sizeof(body), "{\"cpu_percent\":%u}", cpu_percent);
    (void)n;
    http_send_json(pcb, 200, body);
}


void api_register_routes(void) {
    http_register("/api/ping", ping_handler);
    http_register("/api/status", status_handler);
    http_register("/api/network", network_handler);
    http_register("/api/ram", ram_handler);
    http_register("/api/cpu", cpu_handler);
    print_dbg("API routes registered\n");
}
