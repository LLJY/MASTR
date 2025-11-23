#include "mock_wifi.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// Global State
// ============================================================================

// CYW43 driver state (global, matches real driver)
cyw43_t cyw43_state = {0};

// Mock control state
mock_wifi_state_t g_mock_wifi_state = {0};

// ============================================================================
// Mock Control Functions
// ============================================================================

void mock_wifi_reset(void) {
    // Reset CYW43 driver state
    memset(&cyw43_state, 0, sizeof(cyw43_state));

    // Reset mock tracking state
    memset(&g_mock_wifi_state, 0, sizeof(g_mock_wifi_state));

    // Initialize default IP addresses for AP mode (192.168.4.1)
    IP4_ADDR(&cyw43_state.netif[CYW43_ITF_AP].ip_addr, 192, 168, 4, 1);
    IP4_ADDR(&cyw43_state.netif[CYW43_ITF_AP].netmask, 255, 255, 255, 0);
    IP4_ADDR(&cyw43_state.netif[CYW43_ITF_AP].gw, 192, 168, 4, 1);
}

void mock_wifi_set_init_fail(bool should_fail) {
    g_mock_wifi_state.init_should_fail = should_fail;
}

void mock_wifi_set_enable_ap_fail(bool should_fail) {
    g_mock_wifi_state.enable_ap_should_fail = should_fail;
}

void mock_wifi_simulate_client_connect(const uint8_t mac[6]) {
    if (g_mock_wifi_state.connected_client_count >= DHCPS_MAX_IP) {
        printf("WARNING: mock_wifi: Cannot connect more than %d clients\n", DHCPS_MAX_IP);
        return;
    }

    // Check if already connected
    for (int i = 0; i < g_mock_wifi_state.connected_client_count; i++) {
        if (memcmp(g_mock_wifi_state.client_macs[i], mac, 6) == 0) {
            printf("WARNING: mock_wifi: Client already connected\n");
            return;
        }
    }

    // Add new client
    memcpy(g_mock_wifi_state.client_macs[g_mock_wifi_state.connected_client_count],
           mac, 6);
    g_mock_wifi_state.connected_client_count++;
}

void mock_wifi_simulate_client_disconnect(const uint8_t mac[6]) {
    for (int i = 0; i < g_mock_wifi_state.connected_client_count; i++) {
        if (memcmp(g_mock_wifi_state.client_macs[i], mac, 6) == 0) {
            // Remove by shifting remaining clients down
            for (int j = i; j < g_mock_wifi_state.connected_client_count - 1; j++) {
                memcpy(g_mock_wifi_state.client_macs[j],
                       g_mock_wifi_state.client_macs[j + 1], 6);
            }
            g_mock_wifi_state.connected_client_count--;
            return;
        }
    }
    printf("WARNING: mock_wifi: Client not found for disconnect\n");
}

void mock_wifi_simulate_all_clients_disconnect(void) {
    g_mock_wifi_state.connected_client_count = 0;
    memset(g_mock_wifi_state.client_macs, 0, sizeof(g_mock_wifi_state.client_macs));
}

// ============================================================================
// Verification Functions
// ============================================================================

bool mock_wifi_is_initialized(void) {
    return cyw43_state.initialized;
}

bool mock_wifi_is_ap_enabled(void) {
    return cyw43_state.ap_mode_enabled;
}

const char* mock_wifi_get_current_ssid(void) {
    return cyw43_state.ap_ssid;
}

const char* mock_wifi_get_current_password(void) {
    return cyw43_state.ap_password;
}

uint32_t mock_wifi_get_current_auth(void) {
    return cyw43_state.ap_auth;
}

int mock_wifi_get_init_call_count(void) {
    return g_mock_wifi_state.init_call_count;
}

int mock_wifi_get_deinit_call_count(void) {
    return g_mock_wifi_state.deinit_call_count;
}

int mock_wifi_get_enable_ap_call_count(void) {
    return g_mock_wifi_state.enable_ap_call_count;
}

int mock_wifi_get_disable_ap_call_count(void) {
    return g_mock_wifi_state.disable_ap_call_count;
}

const char* mock_wifi_get_last_ap_ssid(void) {
    return g_mock_wifi_state.last_ap_ssid;
}

const char* mock_wifi_get_last_ap_password(void) {
    return g_mock_wifi_state.last_ap_password;
}

uint32_t mock_wifi_get_last_ap_auth(void) {
    return g_mock_wifi_state.last_ap_auth;
}

int mock_wifi_get_connected_client_count(void) {
    return g_mock_wifi_state.connected_client_count;
}

bool mock_wifi_is_client_connected(const uint8_t mac[6]) {
    for (int i = 0; i < g_mock_wifi_state.connected_client_count; i++) {
        if (memcmp(g_mock_wifi_state.client_macs[i], mac, 6) == 0) {
            return true;
        }
    }
    return false;
}

bool mock_wifi_is_dhcp_server_initialized(void) {
    return g_mock_wifi_state.dhcp_server_initialized;
}

void mock_wifi_get_dhcp_ip(ip_addr_t *ip_out) {
    if (ip_out) {
        *ip_out = g_mock_wifi_state.dhcp_ip;
    }
}

void mock_wifi_get_dhcp_netmask(ip_addr_t *nm_out) {
    if (nm_out) {
        *nm_out = g_mock_wifi_state.dhcp_nm;
    }
}

// ============================================================================
// CYW43 WiFi Driver Mock Implementation
// ============================================================================

int cyw43_arch_init(void) {
    g_mock_wifi_state.init_call_count++;

    if (g_mock_wifi_state.init_should_fail) {
        printf("mock_wifi: cyw43_arch_init() -> FAIL (simulated)\n");
        return -1;
    }

    if (cyw43_state.initialized) {
        printf("WARNING: mock_wifi: cyw43_arch_init() called when already initialized\n");
        return -1;
    }

    cyw43_state.initialized = true;
    printf("mock_wifi: cyw43_arch_init() -> OK\n");
    return 0;
}

void cyw43_arch_deinit(void) {
    g_mock_wifi_state.deinit_call_count++;

    if (!cyw43_state.initialized) {
        printf("WARNING: mock_wifi: cyw43_arch_deinit() called when not initialized\n");
        return;
    }

    // Disable AP mode if enabled
    if (cyw43_state.ap_mode_enabled) {
        cyw43_arch_disable_ap_mode();
    }

    cyw43_state.initialized = false;
    printf("mock_wifi: cyw43_arch_deinit()\n");
}

void cyw43_arch_enable_ap_mode(const char *ssid, const char *password, uint32_t auth) {
    g_mock_wifi_state.enable_ap_call_count++;

    if (!cyw43_state.initialized) {
        printf("ERROR: mock_wifi: cyw43_arch_enable_ap_mode() called before init\n");
        return;
    }

    // Store parameters for verification
    if (ssid) {
        strncpy(g_mock_wifi_state.last_ap_ssid, ssid, sizeof(g_mock_wifi_state.last_ap_ssid) - 1);
        g_mock_wifi_state.last_ap_ssid[sizeof(g_mock_wifi_state.last_ap_ssid) - 1] = '\0';

        strncpy(cyw43_state.ap_ssid, ssid, sizeof(cyw43_state.ap_ssid) - 1);
        cyw43_state.ap_ssid[sizeof(cyw43_state.ap_ssid) - 1] = '\0';
    }

    if (password) {
        strncpy(g_mock_wifi_state.last_ap_password, password, sizeof(g_mock_wifi_state.last_ap_password) - 1);
        g_mock_wifi_state.last_ap_password[sizeof(g_mock_wifi_state.last_ap_password) - 1] = '\0';

        strncpy(cyw43_state.ap_password, password, sizeof(cyw43_state.ap_password) - 1);
        cyw43_state.ap_password[sizeof(cyw43_state.ap_password) - 1] = '\0';
    } else {
        g_mock_wifi_state.last_ap_password[0] = '\0';
        cyw43_state.ap_password[0] = '\0';
    }

    g_mock_wifi_state.last_ap_auth = auth;
    cyw43_state.ap_auth = auth;

    // Enable AP mode
    cyw43_state.ap_mode_enabled = true;

    const char *auth_str = (auth == CYW43_AUTH_OPEN) ? "OPEN" :
                          (auth == CYW43_AUTH_WPA2_AES_PSK) ? "WPA2-PSK" :
                          (auth == CYW43_AUTH_WPA_TKIP_PSK) ? "WPA-PSK" : "UNKNOWN";

    printf("mock_wifi: cyw43_arch_enable_ap_mode(ssid='%s', auth=%s)\n",
           ssid ? ssid : "NULL", auth_str);
}

void cyw43_arch_disable_ap_mode(void) {
    g_mock_wifi_state.disable_ap_call_count++;

    if (!cyw43_state.initialized) {
        printf("WARNING: mock_wifi: cyw43_arch_disable_ap_mode() called before init\n");
        return;
    }

    if (!cyw43_state.ap_mode_enabled) {
        printf("WARNING: mock_wifi: cyw43_arch_disable_ap_mode() called when AP not enabled\n");
        return;
    }

    cyw43_state.ap_mode_enabled = false;

    // Disconnect all clients
    mock_wifi_simulate_all_clients_disconnect();

    printf("mock_wifi: cyw43_arch_disable_ap_mode()\n");
}

void cyw43_arch_enable_sta_mode(void) {
    g_mock_wifi_state.enable_sta_call_count++;
    printf("mock_wifi: cyw43_arch_enable_sta_mode() [STUB]\n");
}

void cyw43_arch_disable_sta_mode(void) {
    g_mock_wifi_state.disable_sta_call_count++;
    printf("mock_wifi: cyw43_arch_disable_sta_mode() [STUB]\n");
}

// ============================================================================
// DHCP Server Mock Implementation
// ============================================================================

void dhcp_server_init(dhcp_server_t *d, ip_addr_t *ip, ip_addr_t *nm) {
    if (!d || !ip || !nm) {
        printf("ERROR: mock_wifi: dhcp_server_init() called with NULL parameters\n");
        return;
    }

    // Clear lease table
    memset(d->lease, 0, sizeof(d->lease));

    // Store IP configuration
    d->ip = *ip;
    d->nm = *nm;
    d->udp = NULL;  // Not implementing UDP mock

    // Track in mock state
    g_mock_wifi_state.dhcp_server_initialized = true;
    g_mock_wifi_state.dhcp_ip = *ip;
    g_mock_wifi_state.dhcp_nm = *nm;

    uint32_t ip_val = ip_2_ip4(ip)->addr;
    uint32_t nm_val = ip_2_ip4(nm)->addr;

    printf("mock_wifi: dhcp_server_init(ip=%d.%d.%d.%d, nm=%d.%d.%d.%d)\n",
           (ip_val >> 24) & 0xFF, (ip_val >> 16) & 0xFF,
           (ip_val >> 8) & 0xFF, ip_val & 0xFF,
           (nm_val >> 24) & 0xFF, (nm_val >> 16) & 0xFF,
           (nm_val >> 8) & 0xFF, nm_val & 0xFF);
}

void dhcp_server_deinit(dhcp_server_t *d) {
    if (!d) {
        printf("ERROR: mock_wifi: dhcp_server_deinit() called with NULL\n");
        return;
    }

    // Clear lease table
    memset(d->lease, 0, sizeof(d->lease));
    d->udp = NULL;

    // Track in mock state
    g_mock_wifi_state.dhcp_server_initialized = false;

    printf("mock_wifi: dhcp_server_deinit()\n");
}

// ============================================================================
// API Stubs (for ap_manager.c dependencies)
// ============================================================================

// Stub for api_register_routes() - called by ap_manager.c
void api_register_routes(void) {
    printf("mock_wifi: api_register_routes() called (stub)\n");
}
