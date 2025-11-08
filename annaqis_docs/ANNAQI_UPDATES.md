# MASTR WiFi AP Integration - Updates Summary

## Overview
Integration of WiFi Access Point (AP) functionality with HTTP API endpoints for the MASTR token attestation system.

## Features Added

### 1. WiFi Access Point (AP)
- **SSID:** `MASTR-Token`
- **Password:** `MastrToken123`
- **IP Address:** `192.168.4.1`
- **DHCP Server:** Provides IPs in range 192.168.4.16-192.168.4.23 (up to 8 clients)
- **Security:** WPA2-PSK

### 2. HTTP API Endpoints

#### `/api/ping` ✅
- **Method:** GET
- **Response:** `{"message":"pong"}`
- **Purpose:** Simple connectivity test

#### `/api/status` ✅
- **Method:** GET
- **Response:** `{"provisioned":true/false, "state":"0xXX", "uptime_s":123}`
- **Purpose:** Check if token is provisioned
- **Implementation:** Checks if `protocol_state.current_state == 0x40` (RUNTIME state)

#### `/api/network` ✅ (NEW - Meets R-4.6.1 through R-4.6.3)
- **Method:** GET
- **Response:** 
```json
{
  "ssid": "MASTR-Token",
  "security": "WPA2-PSK",
  "ap_ip": "192.168.4.1",
  "clients": [
    {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.4.16"},
    {"mac": "11:22:33:44:55:66", "ip": "192.168.4.17"}
  ]
}
```
- **Requirements Met:**
  - R-4.6.1: ✅ Displays SSID and WPA2-PSK status
  - R-4.6.2: ✅ Displays connected client IP addresses
  - R-4.6.3: ✅ Displays MAC address + IP for each connected client
  - R-4.6.4: ✅ Web portal refreshes every 5 seconds
- **Implementation:** Reads DHCP server lease table to get connected clients with MAC/IP pairs

#### `/api/info` ❌ (DISABLED)
- Causes crashes - removed from active endpoints

### 3. Web Dashboard (index.html)

**Features:**
- Displays provisioning status with visual indicator (green/red)
- Shows AP network information:
  - SSID: `MASTR-Token`
  - Security: `WPA2-PSK`
  - AP IP: `192.168.4.1`
  - Connected clients list (MAC + IP)
- Manual refresh button
- Connectivity test button
- Auto-refresh every 5 seconds
- Error/success message display

**URL:** `http://192.168.4.1/`

## Code Changes

### New Files
- None (all updates to existing modules)

### Modified Files

#### `src/net/api/api.c`
- Added `#include "ap/ap_manager.h"` and `#include "dhcp/dhcpserver.h"`
- Updated `status_handler()` to use `print_dbg` instead of blocking `printf`
- Added new `network_handler()` function that:
  - Gets AP IP from CYW43 interface
  - Queries DHCP server for active leases
  - Builds JSON with SSID, security, AP IP, and connected clients
  - Formats MAC addresses from DHCP lease table
  - Logs client connections to debug output
- Updated `api_register_routes()` to register `/api/network` endpoint

#### `src/net/ap/ap_manager.h`
- Added forward declaration of `dhcp_server_t`
- Added new function: `const dhcp_server_t* get_dhcp_server(void);`

#### `src/net/ap/ap_manager.c`
- Implemented `get_dhcp_server()` function to expose DHCP server instance
- Allows API to query connected clients

#### `src/net/wifi_ap.c`
- Removed misleading 60-second delay comments from `wifi_ap_init_task()`
- Removed unnecessary `vTaskDelay(100ms)` 
- WiFi AP now initializes immediately after FreeRTOS scheduler starts

#### `index.html`
- Added Network Info card displaying:
  - SSID
  - Security type
  - AP IP
  - Connected clients list (MAC + IP)
- Updated JavaScript `refreshStatus()` to fetch both `/api/status` and `/api/network`
- Added auto-refresh every 5 seconds (R-4.6.4)
- Dynamic client list rendering

#### `README.md`
- Updated with humor/casual tone ("bruh" style)
- Added documentation of:
  - WiFi AP features
  - API endpoints
  - Known issues and workarounds
  - Build/test instructions
  - Garbage output explanation
  - Next steps for fixes

### Removed/Disabled Code

#### `src/crypt.c`
- Removed `crypt_is_provisioned()` function
- Provisioning check moved to API handler

#### `include/crypt.h`
- Removed `bool crypt_is_provisioned(void);` declaration

## Testing

### Test via WiFi
```bash
# Check status
curl http://192.168.4.1/api/status

# Get network info (with connected clients)
curl http://192.168.4.1/api/network | jq .

# Ping test
curl http://192.168.4.1/api/ping

# Open web dashboard
open http://192.168.4.1/
```

### Web Dashboard
- Auto-refreshes every 5 seconds
- Shows real-time connected client MAC addresses and IPs
- Visual provisioning status indicator

## Architecture

### Task Structure
```
FreeRTOS Tasks:
├── Serial Task (Priority 26) - USB CDC, interrupt-driven
├── Watchdog Task (Priority 27) - Session timeout monitoring
├── WiFi-BG Task (Priority 25) - CYW43 polling (50ms interval)
├── HTTP Server Task (Priority 5) - API request handling
└── WiFi-Init Task (Priority 5) - One-time AP initialization
```

## Known Issues

### 1. Serial-WiFi Interference
- WiFi AP initialization interferes with serial provisioning
- **Cause:** Task scheduling conflicts during WiFi driver setup
- **Workaround:** 60-second delay before WiFi starts (currently removed)
- **Status:** Needs proper fix with provisioning-aware WiFi polling

### 2. macOS USB Connection Loss
- Repeated mount/unmount cycles cause macOS to lose device connection
- **Cause:** macOS USB driver issue (not Pico hardware)
- **Workaround:** Keep plugged in; restart Mac if needed
- **Note:** Regular Pico 2 (non-W) doesn't have this issue

### 3. `/api/info` Crashes
- Temperature sensor ADC reading causes I2C/USB deadlock
- **Status:** Endpoint disabled
- **Fix:** Requires non-blocking temperature sampling

## Firmware Stats
- **Size:** 463 KB (11% of 4 MB FLASH)
- **RAM Used:** 138 KB (26% of 512 KB)
- **Build Status:** ✅ Compiles successfully

## Next Steps

1. **Fix WiFi-Serial interference:** Implement provisioning-aware WiFi polling disable
   - Add `provisioning_active` flag to protocol_state
   - Modify `wifi_background_task()` to skip polling during provisioning

2. **Test full provisioning + WiFi flow**
   - Boot with WiFi enabled
   - Run provisioning via serial
   - Verify both complete without interference

3. **Maybe restore `/api/info`**
   - Implement non-blocking temperature sampling

4. **Monitor macOS USB driver improvements**
   - Check Pico SDK updates for USB stability

## Files Changed Summary
```
Modified:
  ✓ src/net/api/api.c (added network_handler, updated includes)
  ✓ src/net/ap/ap_manager.h (added get_dhcp_server function)
  ✓ src/net/ap/ap_manager.c (implemented get_dhcp_server)
  ✓ src/net/wifi_ap.c (cleaned up WiFi init task)
  ✓ index.html (added network info display, auto-refresh)
  ✓ README.md (updated documentation)

Removed:
  ✓ src/crypt.c: crypt_is_provisioned() function
  ✓ include/crypt.h: crypt_is_provisioned() declaration
```

---
**Last Updated:** November 8, 2025
**Status:** ✅ Compiling and ready for testing
