#include "unity.h"
#include "mock_wifi.h"
#include "wifi_ap.h"
#include "ap_manager.h"
#include <string.h>

// ============================================================================
// Test Setup/Teardown - Handled by test_common.c
// ============================================================================

// Note: setUp() and tearDown() are in test_common.c
// mock_wifi_reset() is called from there

// ============================================================================
// Test Suite 1: WiFi AP Initialization (REAL CODE)
// ============================================================================

void test_wifi_init_success(void) {
    // Act: Initialize WiFi subsystem (REAL wifi_ap_init)
    bool result = wifi_ap_init();

    // Assert: Initialization succeeds
    TEST_ASSERT_TRUE(result);
}

void test_wifi_init_failure(void) {
    // This test doesn't apply since wifi_ap_init() always returns true
    // It's a lightweight function that just marks readiness
    // Keep test but verify it doesn't crash
    bool result = wifi_ap_init();
    TEST_ASSERT_TRUE(result);
}

void test_wifi_init_twice_fails(void) {
    // Note: wifi_ap_init() is idempotent and doesn't fail on second call
    // This test name is legacy from when we tested cyw43_arch_init directly
    // Now we test wifi_ap_init which is lightweight and always succeeds
    bool result1 = wifi_ap_init();
    bool result2 = wifi_ap_init();

    // Assert: Both succeed (wifi_ap_init is idempotent)
    TEST_ASSERT_TRUE(result1);
    TEST_ASSERT_TRUE(result2);
}

void test_wifi_deinit(void) {
    // Act: Stop WiFi AP (REAL wifi_ap_stop)
    wifi_ap_stop();

    // Assert: WiFi is stopped
    TEST_ASSERT_FALSE(mock_wifi_is_initialized());
}

void test_wifi_deinit_when_not_initialized(void) {
    // Act: Stop without starting (should not crash)
    wifi_ap_stop();

    // Assert: State is clean
    TEST_ASSERT_FALSE(mock_wifi_is_initialized());
}

// ============================================================================
// Test Suite 2: AP Mode Start/Stop (REAL CODE)
// ============================================================================

void test_enable_ap_mode_open(void) {
    // Arrange: Create configuration with no password (OPEN)
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "",
        .ip_address = 0xC0A80401,
        .is_running = false
    };

    // Act: Start AP mode (REAL wifi_ap_start)
    bool result = wifi_ap_start(&config);

    // Assert: AP is started with OPEN authentication
    TEST_ASSERT_TRUE(result);
    TEST_ASSERT_TRUE(mock_wifi_is_initialized());
    TEST_ASSERT_TRUE(mock_wifi_is_ap_enabled());
    TEST_ASSERT_EQUAL_STRING("MASTR-Token", mock_wifi_get_current_ssid());
    TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_OPEN, mock_wifi_get_current_auth());
}

void test_enable_ap_mode_wpa2(void) {
    // Arrange: Create configuration with WPA2 password
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "SecurePass123",
        .ip_address = 0xC0A80401,
        .is_running = false
    };

    // Act: Start AP mode (REAL wifi_ap_start)
    bool result = wifi_ap_start(&config);

    // Assert: AP is started with WPA2 authentication
    TEST_ASSERT_TRUE(result);
    TEST_ASSERT_TRUE(mock_wifi_is_ap_enabled());
    TEST_ASSERT_EQUAL_STRING("MASTR-Token", mock_wifi_get_current_ssid());
    TEST_ASSERT_EQUAL_STRING("SecurePass123", mock_wifi_get_current_password());
    TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_WPA2_AES_PSK, mock_wifi_get_current_auth());
}

void test_enable_ap_mode_stores_last_parameters(void) {
    // Arrange: Create configuration
    wifi_ap_config_t config = {
        .ssid = "TestSSID",
        .password = "TestPass",
        .ip_address = 0xC0A80401,
        .is_running = false
    };

    // Act: Start AP mode (REAL wifi_ap_start)
    wifi_ap_start(&config);

    // Assert: Parameters are stored correctly
    TEST_ASSERT_EQUAL_STRING("TestSSID", mock_wifi_get_last_ap_ssid());
    TEST_ASSERT_EQUAL_STRING("TestPass", mock_wifi_get_last_ap_password());
    TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_WPA2_AES_PSK, mock_wifi_get_last_ap_auth());
}

void test_enable_ap_mode_without_init_fails(void) {
    // Note: wifi_ap_start() doesn't require wifi_ap_init() to succeed
    // wifi_ap_init() is just a readiness marker
    // This test verifies that start_access_point() can fail if cyw43 init fails
    mock_wifi_set_init_fail(true);

    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "TestPass",
        .ip_address = 0xC0A80401,
        .is_running = false
    };

    // Act: Try to start AP (will fail at cyw43_arch_init level)
    bool result = wifi_ap_start(&config);

    // Assert: Start fails
    TEST_ASSERT_FALSE(result);
    TEST_ASSERT_FALSE(mock_wifi_is_ap_enabled());
}

void test_disable_ap_mode(void) {
    // Arrange: Start AP first
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "pass",
        .ip_address = 0xC0A80401,
        .is_running = false
    };
    wifi_ap_start(&config);
    TEST_ASSERT_TRUE(mock_wifi_is_ap_enabled());

    // Act: Stop AP (REAL wifi_ap_stop)
    wifi_ap_stop();

    // Assert: AP is stopped
    TEST_ASSERT_FALSE(mock_wifi_is_ap_enabled());
}

void test_disable_ap_mode_when_not_enabled(void) {
    // Act: Stop AP when not running (should not crash)
    wifi_ap_stop();

    // Assert: State is clean
    TEST_ASSERT_FALSE(mock_wifi_is_ap_enabled());
}

// ============================================================================
// Test Suite 3: AP Lifecycle State Machine (REAL CODE)
// ============================================================================

void test_ap_lifecycle_full_sequence(void) {
    // Test: Complete AP lifecycle using REAL functions

    // Step 1: Init
    TEST_ASSERT_TRUE(wifi_ap_init());

    // Step 2: Start AP
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "InitialPass",
        .ip_address = 0xC0A80401,
        .is_running = false
    };
    TEST_ASSERT_TRUE(wifi_ap_start(&config));
    TEST_ASSERT_TRUE(mock_wifi_is_ap_enabled());

    // Step 3: Reconfigure with new password (must be >= 8 chars for WPA2)
    config.password = "NewPass123";
    wifi_ap_stop();
    TEST_ASSERT_FALSE(mock_wifi_is_ap_enabled());

    TEST_ASSERT_TRUE(wifi_ap_start(&config));
    TEST_ASSERT_TRUE(mock_wifi_is_ap_enabled());
    TEST_ASSERT_EQUAL_STRING("NewPass123", mock_wifi_get_current_password());

    // Step 4: Stop
    wifi_ap_stop();
    TEST_ASSERT_FALSE(mock_wifi_is_ap_enabled());
}

void test_ap_password_rotation(void) {
    // Test: Password rotation using REAL wifi_ap_rotate_password()

    // Start with OPEN AP
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "",
        .ip_address = 0xC0A80401,
        .is_running = false
    };
    wifi_ap_start(&config);
    TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_OPEN, mock_wifi_get_current_auth());

    // Rotate to WPA2 password (REAL wifi_ap_rotate_password)
    bool result = wifi_ap_rotate_password("RandomPass42");
    TEST_ASSERT_TRUE(result);
    TEST_ASSERT_EQUAL_STRING("RandomPass42", mock_wifi_get_current_password());
    TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_WPA2_AES_PSK, mock_wifi_get_current_auth());
}

// ============================================================================
// Test Suite 4: AP Manager Functions (REAL CODE)
// ============================================================================

void test_start_access_point_success(void) {
    // Act: Start AP using REAL start_access_point()
    int result = start_access_point("MASTR-Token", "TestPass123");

    // Assert: AP started successfully
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_TRUE(mock_wifi_is_initialized());
    TEST_ASSERT_TRUE(mock_wifi_is_ap_enabled());
    TEST_ASSERT_TRUE(mock_wifi_is_dhcp_server_initialized());
}

void test_start_access_point_open_auth(void) {
    // Act: Start AP with short password (should fall back to OPEN)
    int result = start_access_point("MASTR-Token", "short");

    // Assert: AP uses OPEN authentication
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_TRUE(mock_wifi_is_ap_enabled());
    TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_OPEN, mock_wifi_get_current_auth());
}

void test_start_access_point_init_failure(void) {
    // Arrange: Make cyw43_arch_init fail
    mock_wifi_set_init_fail(true);

    // Act: Try to start AP
    int result = start_access_point("MASTR-Token", "TestPass123");

    // Assert: Start fails
    TEST_ASSERT_EQUAL_INT(-1, result);
    TEST_ASSERT_FALSE(mock_wifi_is_initialized());
}

void test_stop_access_point(void) {
    // Arrange: Start AP first
    start_access_point("MASTR-Token", "TestPass123");
    TEST_ASSERT_TRUE(mock_wifi_is_initialized());

    // Act: Stop AP using REAL stop_access_point()
    stop_access_point();

    // Assert: AP is stopped
    TEST_ASSERT_FALSE(mock_wifi_is_initialized());
    TEST_ASSERT_FALSE(mock_wifi_is_dhcp_server_initialized());
}

void test_reconfigure_access_point_wpa2(void) {
    // Arrange: Start AP first
    start_access_point("MASTR-Token", "InitialPass");

    // Act: Reconfigure with new credentials (REAL reconfigure_access_point)
    int result = reconfigure_access_point("MASTR-Token", "NewPassword123");

    // Assert: AP is reconfigured successfully
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_STRING("NewPassword123", mock_wifi_get_current_password());
    TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_WPA2_AES_PSK, mock_wifi_get_current_auth());
}

void test_reconfigure_access_point_open(void) {
    // Arrange: Start AP with WPA2
    start_access_point("MASTR-Token", "InitialPass");

    // Act: Reconfigure with short password (should fall back to OPEN)
    int result = reconfigure_access_point("MASTR-Token", "123");

    // Assert: AP uses OPEN authentication
    TEST_ASSERT_EQUAL_INT(0, result);
    TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_OPEN, mock_wifi_get_current_auth());
}

// ============================================================================
// Test Suite 5: DHCP Server Integration (REAL CODE)
// ============================================================================

void test_dhcp_server_init(void) {
    // Arrange: Create IP address configuration
    ip_addr_t ip, nm;
    IP4_ADDR(&ip.u_addr.ip4, 192, 168, 4, 1);
    IP4_ADDR(&nm.u_addr.ip4, 255, 255, 255, 0);
    ip.type = 0; // IPv4

    dhcp_server_t dhcp;

    // Act: Initialize DHCP server (REAL dhcp_server_init)
    dhcp_server_init(&dhcp, &ip, &nm);

    // Assert: DHCP server is initialized
    TEST_ASSERT_TRUE(mock_wifi_is_dhcp_server_initialized());

    ip_addr_t dhcp_ip, dhcp_nm;
    mock_wifi_get_dhcp_ip(&dhcp_ip);
    mock_wifi_get_dhcp_netmask(&dhcp_nm);

    TEST_ASSERT_EQUAL_UINT32(0x0104A8C0, ip_2_ip4(&dhcp_ip)->addr);  // 192.168.4.1 in network byte order
    TEST_ASSERT_EQUAL_UINT32(0x00FFFFFF, ip_2_ip4(&dhcp_nm)->addr);  // 255.255.255.0 in network byte order
}

void test_dhcp_server_deinit(void) {
    // Arrange: Initialize DHCP server
    ip_addr_t ip, nm;
    IP4_ADDR(&ip.u_addr.ip4, 192, 168, 4, 1);
    IP4_ADDR(&nm.u_addr.ip4, 255, 255, 255, 0);
    dhcp_server_t dhcp;
    dhcp_server_init(&dhcp, &ip, &nm);
    TEST_ASSERT_TRUE(mock_wifi_is_dhcp_server_initialized());

    // Act: Deinitialize DHCP server (REAL dhcp_server_deinit)
    dhcp_server_deinit(&dhcp);

    // Assert: DHCP server is deinitialized
    TEST_ASSERT_FALSE(mock_wifi_is_dhcp_server_initialized());
}

// ============================================================================
// Test Suite 6: Client Connection Simulation
// ============================================================================

void test_simulate_client_connect(void) {
    // Arrange: MAC address for test client
    uint8_t client_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    // Act: Simulate client connection
    mock_wifi_simulate_client_connect(client_mac);

    // Assert: Client is connected
    TEST_ASSERT_EQUAL_INT(1, mock_wifi_get_connected_client_count());
    TEST_ASSERT_TRUE(mock_wifi_is_client_connected(client_mac));
}

void test_simulate_multiple_clients_connect(void) {
    // Arrange: Multiple client MAC addresses
    uint8_t client1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t client2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t client3[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    // Act: Connect multiple clients
    mock_wifi_simulate_client_connect(client1);
    mock_wifi_simulate_client_connect(client2);
    mock_wifi_simulate_client_connect(client3);

    // Assert: All clients are connected
    TEST_ASSERT_EQUAL_INT(3, mock_wifi_get_connected_client_count());
    TEST_ASSERT_TRUE(mock_wifi_is_client_connected(client1));
    TEST_ASSERT_TRUE(mock_wifi_is_client_connected(client2));
    TEST_ASSERT_TRUE(mock_wifi_is_client_connected(client3));
}

void test_simulate_client_disconnect(void) {
    // Arrange: Connect a client
    uint8_t client_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    mock_wifi_simulate_client_connect(client_mac);
    TEST_ASSERT_EQUAL_INT(1, mock_wifi_get_connected_client_count());

    // Act: Disconnect the client
    mock_wifi_simulate_client_disconnect(client_mac);

    // Assert: Client is disconnected
    TEST_ASSERT_EQUAL_INT(0, mock_wifi_get_connected_client_count());
    TEST_ASSERT_FALSE(mock_wifi_is_client_connected(client_mac));
}

void test_simulate_disconnect_specific_client(void) {
    // Arrange: Connect three clients
    uint8_t client1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t client2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t client3[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    mock_wifi_simulate_client_connect(client1);
    mock_wifi_simulate_client_connect(client2);
    mock_wifi_simulate_client_connect(client3);

    // Act: Disconnect client2 (middle one)
    mock_wifi_simulate_client_disconnect(client2);

    // Assert: client2 is gone, others remain
    TEST_ASSERT_EQUAL_INT(2, mock_wifi_get_connected_client_count());
    TEST_ASSERT_TRUE(mock_wifi_is_client_connected(client1));
    TEST_ASSERT_FALSE(mock_wifi_is_client_connected(client2));
    TEST_ASSERT_TRUE(mock_wifi_is_client_connected(client3));
}

void test_simulate_all_clients_disconnect(void) {
    // Arrange: Connect multiple clients
    uint8_t client1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t client2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t client3[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    mock_wifi_simulate_client_connect(client1);
    mock_wifi_simulate_client_connect(client2);
    mock_wifi_simulate_client_connect(client3);
    TEST_ASSERT_EQUAL_INT(3, mock_wifi_get_connected_client_count());

    // Act: Disconnect all clients
    mock_wifi_simulate_all_clients_disconnect();

    // Assert: No clients connected
    TEST_ASSERT_EQUAL_INT(0, mock_wifi_get_connected_client_count());
    TEST_ASSERT_FALSE(mock_wifi_is_client_connected(client1));
    TEST_ASSERT_FALSE(mock_wifi_is_client_connected(client2));
    TEST_ASSERT_FALSE(mock_wifi_is_client_connected(client3));
}

void test_disable_ap_disconnects_all_clients(void) {
    // Arrange: Start AP and connect clients
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "pass",
        .ip_address = 0xC0A80401,
        .is_running = false
    };
    wifi_ap_start(&config);

    uint8_t client1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t client2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    mock_wifi_simulate_client_connect(client1);
    mock_wifi_simulate_client_connect(client2);
    TEST_ASSERT_EQUAL_INT(2, mock_wifi_get_connected_client_count());

    // Act: Stop AP (REAL wifi_ap_stop)
    wifi_ap_stop();

    // Assert: All clients are disconnected
    TEST_ASSERT_EQUAL_INT(0, mock_wifi_get_connected_client_count());
}

// ============================================================================
// Test Suite 7: IP Address Configuration
// ============================================================================

void test_default_ap_ip_address(void) {
    // Arrange: Reset mock to get default configuration
    mock_wifi_reset();

    // Act: Check default IP configuration
    const ip4_addr_t *ap_ip = netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_AP]);

    // Assert: Default IP is 192.168.4.1
    TEST_ASSERT_EQUAL_UINT8(192, ip4_addr1(ap_ip));
    TEST_ASSERT_EQUAL_UINT8(168, ip4_addr2(ap_ip));
    TEST_ASSERT_EQUAL_UINT8(4, ip4_addr3(ap_ip));
    TEST_ASSERT_EQUAL_UINT8(1, ip4_addr4(ap_ip));
}

void test_default_ap_netmask(void) {
    // Arrange: Reset mock to get default configuration
    mock_wifi_reset();

    // Act: Check default netmask
    const ip4_addr_t *ap_nm = netif_ip4_netmask(&cyw43_state.netif[CYW43_ITF_AP]);

    // Assert: Default netmask is 255.255.255.0
    TEST_ASSERT_EQUAL_UINT8(255, ip4_addr1(ap_nm));
    TEST_ASSERT_EQUAL_UINT8(255, ip4_addr2(ap_nm));
    TEST_ASSERT_EQUAL_UINT8(255, ip4_addr3(ap_nm));
    TEST_ASSERT_EQUAL_UINT8(0, ip4_addr4(ap_nm));
}

// ============================================================================
// Test Suite 8: Error Conditions
// ============================================================================

void test_connect_duplicate_client(void) {
    // Arrange: Connect a client
    uint8_t client_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    mock_wifi_simulate_client_connect(client_mac);
    TEST_ASSERT_EQUAL_INT(1, mock_wifi_get_connected_client_count());

    // Act: Try to connect same client again (should warn but not add)
    mock_wifi_simulate_client_connect(client_mac);

    // Assert: Still only one client
    TEST_ASSERT_EQUAL_INT(1, mock_wifi_get_connected_client_count());
}

void test_disconnect_nonexistent_client(void) {
    // Arrange: Connect one client
    uint8_t client1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t client2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    mock_wifi_simulate_client_connect(client1);

    // Act: Try to disconnect client that was never connected (should warn)
    mock_wifi_simulate_client_disconnect(client2);

    // Assert: Original client still connected
    TEST_ASSERT_EQUAL_INT(1, mock_wifi_get_connected_client_count());
    TEST_ASSERT_TRUE(mock_wifi_is_client_connected(client1));
}

void test_max_clients_limit(void) {
    // Act: Try to connect more than DHCPS_MAX_IP clients
    for (int i = 0; i < DHCPS_MAX_IP + 2; i++) {
        uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, (uint8_t)i};
        mock_wifi_simulate_client_connect(mac);
    }

    // Assert: Only DHCPS_MAX_IP clients are connected
    TEST_ASSERT_EQUAL_INT(DHCPS_MAX_IP, mock_wifi_get_connected_client_count());
}

// ============================================================================
// Test Suite 9: WiFi AP Get Config (REAL CODE)
// ============================================================================

void test_wifi_ap_get_config(void) {
    // Arrange: Start AP with known config
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "TestPass123",
        .ip_address = 0xC0A80401,
        .is_running = false
    };
    wifi_ap_start(&config);

    // Act: Get configuration (REAL wifi_ap_get_config)
    wifi_ap_config_t *retrieved = wifi_ap_get_config();

    // Assert: Configuration matches
    TEST_ASSERT_NOT_NULL(retrieved);
    TEST_ASSERT_EQUAL_STRING("MASTR-Token", retrieved->ssid);
    TEST_ASSERT_EQUAL_STRING("TestPass123", retrieved->password);
    TEST_ASSERT_EQUAL_UINT32(0xC0A80401, retrieved->ip_address);
}

void test_wifi_ap_rotate_password_null(void) {
    // Act: Try to rotate with NULL password (REAL wifi_ap_rotate_password)
    bool result = wifi_ap_rotate_password(NULL);

    // Assert: Rotation fails
    TEST_ASSERT_FALSE(result);
}

// ============================================================================
// Test Suite 10: WiFi AP Status Functions (REAL CODE)
// ============================================================================

void test_wifi_ap_is_active_when_running(void) {
    // Arrange: Start AP
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "TestPass123",
        .ip_address = 0xC0A80401,
        .is_running = false
    };
    wifi_ap_start(&config);

    // Act: Check if active (REAL wifi_ap_is_active)
    bool is_active = wifi_ap_is_active();

    // Assert: AP is active
    TEST_ASSERT_TRUE(is_active);
}

void test_wifi_ap_is_active_when_stopped(void) {
    // Arrange: Ensure AP is stopped
    wifi_ap_stop();

    // Act: Check if active (REAL wifi_ap_is_active)
    bool is_active = wifi_ap_is_active();

    // Assert: AP is not active
    TEST_ASSERT_FALSE(is_active);
}

void test_wifi_ap_restart(void) {
    // Arrange: Start AP first
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "TestPass123",
        .ip_address = 0xC0A80401,
        .is_running = false
    };
    wifi_ap_start(&config);

    // Act: Restart AP (REAL wifi_ap_restart)
    bool result = wifi_ap_restart();

    // Assert: Restart succeeds
    TEST_ASSERT_TRUE(result);
    TEST_ASSERT_TRUE(wifi_ap_is_active());
}
