#include "ap_manager.h"

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include <string.h>
#include "lwip/ip4_addr.h"
#include "dhcp/dhcpserver.h"
#include "http/http_server.h"
#include "api/api.h"
#include "FreeRTOS.h"
#include "task.h"
#include "serial.h"

static dhcp_server_t g_dhcp;

// Convert const ip4_addr_t to an ip_addr_t (lwIP type)
static void ip4_to_ipaddr(const ip4_addr_t *in, ip_addr_t *out) {
    IP4_ADDR(ip_2_ip4(out), ip4_addr1(in), ip4_addr2(in), ip4_addr3(in), ip4_addr4(in));
}

int start_access_point(const char *ssid, const char *pass) {
    if (cyw43_arch_init()) {
        print_dbg("ERROR: cyw43_arch_init failed\n");
        return -1;
    }

    // Ensure passphrase length is valid for WPA2 (>= 8). If not, fall back
    // to an open AP so the client can at least associate for debugging.
    const char *ap_pass = pass;
    int auth_mode = CYW43_AUTH_WPA2_AES_PSK;
    if (pass == NULL || strlen(pass) < 8) {
        auth_mode = CYW43_AUTH_OPEN;
        ap_pass = ""; // driver will treat this as open
        print_dbg("WARNING: WiFi password too short, using open AP\n");
    }

    cyw43_arch_enable_ap_mode(ssid, ap_pass, auth_mode);
    const ip4_addr_t *ap_ip4 = netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_AP]);
    const ip4_addr_t *ap_nm4 = netif_ip4_netmask(&cyw43_state.netif[CYW43_ITF_AP]);

    // Use non-blocking approach: wait briefly but yield to other tasks
    // This prevents blocking serial provisioning
    int retries = 20; // up to ~2 seconds, but each retry yields
    while (retries-- > 0) {
        ap_ip4 = netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_AP]);
        ap_nm4 = netif_ip4_netmask(&cyw43_state.netif[CYW43_ITF_AP]);
        if (ap_ip4 && ip4_addr_get_u32(ap_ip4) != 0) break;
        // Use vTaskDelay instead of sleep_ms to allow task switching
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ip_addr_t ip, nm;
    ip4_to_ipaddr(ap_ip4, &ip);
    ip4_to_ipaddr(ap_nm4, &nm);

    dhcp_server_init(&g_dhcp, &ip, &nm);

    // Start HTTP API server
    http_server_init();

    // Register API routes
    api_register_routes();

    print_dbg("WiFi AP started: SSID=%s (192.168.4.1)\n", ssid);
    
    return 0;
}

void stop_access_point(void) {
    dhcp_server_deinit(&g_dhcp);
    cyw43_arch_deinit();
    print_dbg("WiFi AP stopped\n");
}

int reconfigure_access_point(const char *ssid, const char *pass) {
    // Determine auth mode and password
    const char *ap_pass = pass;
    int auth_mode = CYW43_AUTH_WPA2_AES_PSK;
    if (pass == NULL || strlen(pass) < 8) {
        auth_mode = CYW43_AUTH_OPEN;
        ap_pass = "";
        print_dbg("Reconfiguring AP to OPEN (password too short)\n");
    } else {
        print_dbg("Reconfiguring AP to WPA2-PSK\n");
    }

    // Disable AP mode then re-enable with new credentials (keep driver/lwIP alive)
    cyw43_arch_disable_ap_mode();
    cyw43_arch_enable_ap_mode(ssid, ap_pass, auth_mode);

    // Keep existing DHCP server; IP/netmask are unchanged
    print_dbg("AP reconfigured: SSID=%s, auth=%s\n", ssid,
              (auth_mode == CYW43_AUTH_OPEN) ? "OPEN" : "WPA2-PSK");
    return 0;
}



/**
 * Get DHCP server instance for querying connected clients
 */
const dhcp_server_t* get_dhcp_server(void) {
    return &g_dhcp;
}
