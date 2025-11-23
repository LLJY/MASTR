#ifndef MOCK_WIFI_H
#define MOCK_WIFI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "mock_lwip.h"
#include "dhcpserver.h"

// ============================================================================
// CYW43 WiFi Driver Mock
// ============================================================================
// This mock simulates the Raspberry Pi Pico W WiFi driver (cyw43_arch) for
// unit testing WiFi AP management code without real hardware.
//
// Key Features:
// - Tracks AP init/deinit/enable/disable state transitions
// - Simulates SSID, password, and auth mode configuration
// - Tracks connected clients (simulated)
// - Verifies call sequences and parameters
// - NO FAKE TESTS: All state changes are truthfully tracked
//
// Usage:
// 1. Call mock_wifi_reset() before each test
// 2. Use mock_wifi_* functions to verify AP behavior
// 3. Use mock_wifi_simulate_* to inject test conditions
// ============================================================================

// --- CYW43 Constants (from pico-sdk) ---

// WiFi authentication modes
#define CYW43_AUTH_OPEN           (0)             // No authentication (open AP)
#define CYW43_AUTH_WPA_TKIP_PSK   (0x00200002)    // WPA-PSK with TKIP
#define CYW43_AUTH_WPA2_AES_PSK   (0x00400004)    // WPA2-PSK with AES (preferred)
#define CYW43_AUTH_WPA2_MIXED_PSK (0x00400006)    // WPA2 Mixed mode

// WiFi interface types
#define CYW43_ITF_STA (0)  // Station (client) mode
#define CYW43_ITF_AP  (1)  // Access Point mode

// Link status (for STA mode, AP is always DOWN)
#define CYW43_LINK_DOWN       (0)
#define CYW43_LINK_JOIN       (1)
#define CYW43_LINK_NOIP       (2)
#define CYW43_LINK_UP         (3)
#define CYW43_LINK_FAIL       (-1)
#define CYW43_LINK_NONET      (-2)
#define CYW43_LINK_BADAUTH    (-3)

// --- lwIP Mock Types ---
// Note: IP address types are now defined in mock_lwip.h

// Network interface structure (simplified mock)
typedef struct {
    ip4_addr_t ip_addr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
    uint8_t hwaddr[6];  // MAC address
} netif_t;

// Accessor functions (from lwip/netif.h)
#define netif_ip4_addr(netif)    (&(netif)->ip_addr)
#define netif_ip4_netmask(netif) (&(netif)->netmask)
#define netif_ip4_gw(netif)      (&(netif)->gw)

// --- CYW43 Driver State (Global) ---
// Note: DHCP server types are defined in dhcpserver.h

// Forward declaration
typedef struct cyw43_t cyw43_t;

// CYW43 driver state structure (simplified)
struct cyw43_t {
    netif_t netif[2];  // [0] = STA, [1] = AP
    dhcp_server_t dhcp_server;

    // AP state tracking
    bool ap_mode_enabled;
    char ap_ssid[33];
    char ap_password[64];
    uint32_t ap_auth;

    // Initialization state
    bool initialized;
};

// Global CYW43 state (matches real driver)
extern cyw43_t cyw43_state;

// --- CYW43 WiFi Functions (Mock Implementations) ---

// Core initialization/deinitialization
int cyw43_arch_init(void);
void cyw43_arch_deinit(void);

// AP mode control
void cyw43_arch_enable_ap_mode(const char *ssid, const char *password, uint32_t auth);
void cyw43_arch_disable_ap_mode(void);

// STA mode control (basic stubs for completeness)
void cyw43_arch_enable_sta_mode(void);
void cyw43_arch_disable_sta_mode(void);

// --- Mock Control & Verification API ---

// Mock state tracking
typedef struct {
    // Call counters
    int init_call_count;
    int deinit_call_count;
    int enable_ap_call_count;
    int disable_ap_call_count;
    int enable_sta_call_count;
    int disable_sta_call_count;

    // Last call parameters (for AP mode)
    char last_ap_ssid[33];
    char last_ap_password[64];
    uint32_t last_ap_auth;

    // Behavior control
    bool init_should_fail;
    bool enable_ap_should_fail;

    // Simulated client connections
    int connected_client_count;
    uint8_t client_macs[DHCPS_MAX_IP][6];

    // DHCP server tracking
    bool dhcp_server_initialized;
    ip_addr_t dhcp_ip;
    ip_addr_t dhcp_nm;
} mock_wifi_state_t;

extern mock_wifi_state_t g_mock_wifi_state;

// --- Test Control Functions ---

// Reset mock state (call before each test)
void mock_wifi_reset(void);

// Set failure conditions
void mock_wifi_set_init_fail(bool should_fail);
void mock_wifi_set_enable_ap_fail(bool should_fail);

// Simulate client connections
void mock_wifi_simulate_client_connect(const uint8_t mac[6]);
void mock_wifi_simulate_client_disconnect(const uint8_t mac[6]);
void mock_wifi_simulate_all_clients_disconnect(void);

// --- Verification Functions ---

// Check AP state
bool mock_wifi_is_initialized(void);
bool mock_wifi_is_ap_enabled(void);
const char* mock_wifi_get_current_ssid(void);
const char* mock_wifi_get_current_password(void);
uint32_t mock_wifi_get_current_auth(void);

// Check call counts
int mock_wifi_get_init_call_count(void);
int mock_wifi_get_deinit_call_count(void);
int mock_wifi_get_enable_ap_call_count(void);
int mock_wifi_get_disable_ap_call_count(void);

// Check last call parameters
const char* mock_wifi_get_last_ap_ssid(void);
const char* mock_wifi_get_last_ap_password(void);
uint32_t mock_wifi_get_last_ap_auth(void);

// Check connected clients
int mock_wifi_get_connected_client_count(void);
bool mock_wifi_is_client_connected(const uint8_t mac[6]);

// Check DHCP server state
bool mock_wifi_is_dhcp_server_initialized(void);
void mock_wifi_get_dhcp_ip(ip_addr_t *ip_out);
void mock_wifi_get_dhcp_netmask(ip_addr_t *nm_out);

#endif // MOCK_WIFI_H
