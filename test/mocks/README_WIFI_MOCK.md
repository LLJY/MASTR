# WiFi AP Mock - Quick Start Guide

## Overview

Mock implementation of Raspberry Pi Pico W's CYW43 WiFi driver for unit testing WiFi Access Point functionality without hardware.

## Files

- `mock_wifi.h` - Header with all CYW43/lwIP types and function declarations (340 lines)
- `mock_wifi.c` - Mock implementation with state tracking (370 lines)
- `../test_wifi_ap.c` - Comprehensive test suite with 30 test cases (430 lines)
- `../WIFI_MOCK_ANALYSIS.md` - Full documentation and analysis

## Quick Usage

### 1. Basic Test Structure

```c
#include "unity.h"
#include "mock_wifi.h"

void setUp(void) {
    mock_wifi_reset();  // Always reset before each test
}

void tearDown(void) {
    // Cleanup
}

void test_enable_ap(void) {
    // Arrange
    cyw43_arch_init();

    // Act
    cyw43_arch_enable_ap_mode("MyAP", "password", CYW43_AUTH_WPA2_AES_PSK);

    // Assert
    TEST_ASSERT_TRUE(mock_wifi_is_ap_enabled());
    TEST_ASSERT_EQUAL_STRING("MyAP", mock_wifi_get_current_ssid());
}
```

### 2. Common Test Patterns

#### Test Init/Deinit Sequence
```c
cyw43_arch_init();
TEST_ASSERT_TRUE(mock_wifi_is_initialized());
cyw43_arch_deinit();
TEST_ASSERT_FALSE(mock_wifi_is_initialized());
```

#### Test AP Configuration
```c
cyw43_arch_enable_ap_mode("SSID", "pass", CYW43_AUTH_WPA2_AES_PSK);
TEST_ASSERT_EQUAL_STRING("SSID", mock_wifi_get_last_ap_ssid());
TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_WPA2_AES_PSK, mock_wifi_get_last_ap_auth());
```

#### Test Password Rotation
```c
// Initial OPEN mode
cyw43_arch_enable_ap_mode("AP", "", CYW43_AUTH_OPEN);
TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_OPEN, mock_wifi_get_current_auth());

// Rotate to WPA2
cyw43_arch_disable_ap_mode();
cyw43_arch_enable_ap_mode("AP", "newpass", CYW43_AUTH_WPA2_AES_PSK);
TEST_ASSERT_EQUAL_STRING("newpass", mock_wifi_get_current_password());
```

#### Simulate Client Connections
```c
uint8_t client[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
mock_wifi_simulate_client_connect(client);
TEST_ASSERT_EQUAL_INT(1, mock_wifi_get_connected_client_count());
TEST_ASSERT_TRUE(mock_wifi_is_client_connected(client));
```

#### Test DHCP Server
```c
ip_addr_t ip, nm;
IP4_ADDR(&ip.u_addr.ip4, 192, 168, 4, 1);
IP4_ADDR(&nm.u_addr.ip4, 255, 255, 255, 0);

dhcp_server_t dhcp;
dhcp_server_init(&dhcp, &ip, &nm);
TEST_ASSERT_TRUE(mock_wifi_is_dhcp_server_initialized());
```

#### Inject Failures
```c
mock_wifi_set_init_fail(true);
int result = cyw43_arch_init();
TEST_ASSERT_EQUAL_INT(-1, result);
TEST_ASSERT_FALSE(mock_wifi_is_initialized());
```

### 3. Verification API

#### State Checks
- `mock_wifi_is_initialized()` - Is driver initialized?
- `mock_wifi_is_ap_enabled()` - Is AP mode active?
- `mock_wifi_get_current_ssid()` - Current AP SSID
- `mock_wifi_get_current_password()` - Current AP password
- `mock_wifi_get_current_auth()` - Current auth mode

#### Call Counts
- `mock_wifi_get_init_call_count()` - Times init was called
- `mock_wifi_get_deinit_call_count()` - Times deinit was called
- `mock_wifi_get_enable_ap_call_count()` - Times AP was enabled
- `mock_wifi_get_disable_ap_call_count()` - Times AP was disabled

#### Last Parameters
- `mock_wifi_get_last_ap_ssid()` - Last SSID passed to enable_ap
- `mock_wifi_get_last_ap_password()` - Last password passed
- `mock_wifi_get_last_ap_auth()` - Last auth mode passed

#### Client Tracking
- `mock_wifi_get_connected_client_count()` - Number of connected clients
- `mock_wifi_is_client_connected(mac)` - Is specific client connected?

#### DHCP State
- `mock_wifi_is_dhcp_server_initialized()` - Is DHCP running?
- `mock_wifi_get_dhcp_ip(ip_out)` - Get DHCP server IP
- `mock_wifi_get_dhcp_netmask(nm_out)` - Get DHCP netmask

### 4. Authentication Modes

```c
#define CYW43_AUTH_OPEN           (0)             // No password
#define CYW43_AUTH_WPA_TKIP_PSK   (0x00200002)    // WPA (legacy)
#define CYW43_AUTH_WPA2_AES_PSK   (0x00400004)    // WPA2 (preferred)
```

### 5. IP Address Helpers

```c
// Set IP address
ip_addr_t ip;
IP4_ADDR(&ip.u_addr.ip4, 192, 168, 4, 1);  // 192.168.4.1

// Access netif IP
const ip4_addr_t *ap_ip = netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_AP]);
uint8_t octet1 = ip4_addr1(ap_ip);  // First octet
```

## Test Coverage

**30 test cases across 7 suites:**
1. Initialization (5 tests)
2. AP Mode Control (6 tests)
3. Lifecycle State Machine (2 tests)
4. DHCP Integration (2 tests)
5. Client Simulation (6 tests)
6. IP Configuration (2 tests)
7. Error Conditions (3 tests)

## Running Tests

```bash
cd test/build
cmake ..
make test_wifi_ap
./test_wifi_ap
```

## Design Principles

✅ **NO FAKE TESTS** - All state changes are truthfully tracked
✅ **Call Verification** - Every function call is counted
✅ **Parameter Tracking** - All function parameters stored for verification
✅ **Failure Injection** - Can simulate init failures, max clients
✅ **Verbose Logging** - Debug output shows exact call sequences

## Common Pitfalls

❌ **Forgetting mock_wifi_reset()** - Always call in setUp()
❌ **Not initializing before enabling AP** - Must call cyw43_arch_init() first
❌ **Exceeding DHCPS_MAX_IP clients** - Max 8 clients can connect
❌ **Checking state before action** - State only changes after function returns

## Example: Full AP Lifecycle Test

```c
void test_ap_lifecycle(void) {
    // Init driver
    TEST_ASSERT_EQUAL_INT(0, cyw43_arch_init());
    TEST_ASSERT_TRUE(mock_wifi_is_initialized());

    // Enable AP (OPEN mode for provisioning)
    cyw43_arch_enable_ap_mode("MASTR", "", CYW43_AUTH_OPEN);
    TEST_ASSERT_TRUE(mock_wifi_is_ap_enabled());
    TEST_ASSERT_EQUAL_UINT32(CYW43_AUTH_OPEN, mock_wifi_get_current_auth());

    // Simulate client connecting
    uint8_t client[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    mock_wifi_simulate_client_connect(client);
    TEST_ASSERT_EQUAL_INT(1, mock_wifi_get_connected_client_count());

    // Rotate password (post-claim)
    cyw43_arch_disable_ap_mode();
    cyw43_arch_enable_ap_mode("MASTR", "Secure123", CYW43_AUTH_WPA2_AES_PSK);
    TEST_ASSERT_EQUAL_STRING("Secure123", mock_wifi_get_current_password());
    TEST_ASSERT_EQUAL_INT(0, mock_wifi_get_connected_client_count()); // Clients disconnected

    // Cleanup
    cyw43_arch_deinit();
    TEST_ASSERT_FALSE(mock_wifi_is_initialized());

    // Verify call counts
    TEST_ASSERT_EQUAL_INT(1, mock_wifi_get_init_call_count());
    TEST_ASSERT_EQUAL_INT(2, mock_wifi_get_enable_ap_call_count());
    TEST_ASSERT_EQUAL_INT(2, mock_wifi_get_disable_ap_call_count());
    TEST_ASSERT_EQUAL_INT(1, mock_wifi_get_deinit_call_count());
}
```

## Documentation

See `WIFI_MOCK_ANALYSIS.md` for:
- Complete function list from source code analysis
- AP lifecycle state machine diagram
- DHCP server integration details
- Hardware dependencies NOT mocked
- Future enhancement ideas

## Questions?

Check the full analysis document or look at the 30 test cases in `test_wifi_ap.c` for more examples.
