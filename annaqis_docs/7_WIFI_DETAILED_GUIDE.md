# WiFi Detailed Technical Guide

Complete reference for WiFi AP integration including HTTP handlers, debugging, and advanced configuration.

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│ Pico W / RP2350-W Hardware                                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CYW43 WiFi Chip (2.4 GHz)                                │
│  ├─ Interface 0: Station (disabled in AP mode)            │
│  └─ Interface 1: Access Point (enabled)                  │
│                                                             │
│  lwIP Stack                                                │
│  ├─ ARP / IP / UDP / TCP layers                          │
│  ├─ DHCP Server (192.168.4.1 gateway)                    │
│  └─ HTTP Server (listening on port 80)                   │
│                                                             │
│  FreeRTOS Kernel                                           │
│  ├─ Serial Task (26) - Protocol processing               │
│  ├─ WiFi-BG Task (25) - CYW43 polling                    │
│  └─ HTTP Task (10) - Socket I/O                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## CYW43 Driver Initialization

### What wifi_ap_init() Does

```c
bool wifi_ap_init(void) {
    // 1. Initialize CYW43 driver hardware
    if (cyw43_arch_init()) {
        return false;  // Chip communication failed
    }
    
    // 2. Set AP mode (disables STA interface)
    cyw43_arch_enable_ap_mode();
    
    // 3. Power on WiFi radio
    // (handled automatically by cyw43_arch_enable_ap_mode)
    
    return true;
}
```

### CYW43 Internal States

After `wifi_ap_init()`:

```
┌─────────────────────┐
│ Initialization (1ms)│
└──────────┬──────────┘
           │
           ↓ cyw43_arch_init()
┌──────────────────────┐
│ Driver ready (radio off)
└──────────┬───────────┘
           │
           ↓ cyw43_arch_enable_ap_mode()
┌─────────────────────┐
│ AP mode (radio on)  │
│ Waiting for config  │
└──────────┬──────────┘
           │
           ↓ wifi_ap_start() with config
┌─────────────────────┐
│ SSID broadcasting   │
│ DHCP ready          │
│ HTTP listening      │
└─────────────────────┘
```

## lwIP Stack Configuration

### DHCP Server Setup

In `wifi_ap_start()`:

```c
// Create IP addresses
ip4_addr_t gw;
IP4_ADDR(&gw, 192, 168, 4, 1);      // Gateway (AP itself)

ip4_addr_t mask;
IP4_ADDR(&mask, 255, 255, 255, 0);  // /24 subnet mask

// Get the AP netif (Interface 1)
struct netif *ap_netif = &cyw43_state.netif[1];

// Configure interface
netif_set_ipaddr(ap_netif, &gw);    // Set IP
netif_set_netmask(ap_netif, &mask);  // Set netmask
netif_set_gw(ap_netif, &gw);         // Set gateway
netif_set_up(ap_netif);              // Bring interface up

// Start DHCP server
dhcp_server_init(ap_netif, &gw, &mask);
```

### DHCP IP Range

With gateway 192.168.4.1 and /24 netmask:

```
Network:        192.168.4.0/24
Gateway:        192.168.4.1 (Pico W itself)
DHCP Pool:      192.168.4.2 - 192.168.4.254
Broadcast:      192.168.4.255

Example assignments:
- Client 1:     192.168.4.2
- Client 2:     192.168.4.3
- Client 3:     192.168.4.4
- ...
```

### Why Not 192.168.1.x?

Common routers use 192.168.1.x. We use 192.168.4.x to:
- Avoid IP conflicts if clients connected to router
- Allow devices on both networks to reach token
- Clearly identify AP network as separate

## WiFi Background Task Details

### Polling Loop

```c
void wifi_background_task(void *params) {
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(50));  // Wait 50ms
        
        // Process CYW43 events
        cyw43_arch_poll();  // May not be called explicitly
        
        // lwIP timers run automatically when packets arrive
    }
}
```

### What Happens Every 50ms

```
T=0ms:    WiFi Task wakes from sleep
          │
          ├─ Check pending WiFi events
          │  ├─ Any beacon to send? (AP advertisement)
          │  ├─ Any RX packets? (client data)
          │  ├─ Any TX buffers ready? (send to client)
          │  └─ Any timeouts? (client inactivity)
          │
          ├─ Call lwIP handlers (if packets arrived)
          │  ├─ DHCP renew checks
          │  ├─ TCP timeout checks
          │  └─ UDP timeout checks
          │
          └─ Return to sleep until next 50ms tick

T=50ms:   Wake again, repeat
```

### Critical: Why It Must Run Regularly

If WiFi task blocked for > 100ms:

```
CYW43 Internal State:
- Pending packets in RX buffer
- Timer counting down
- No cyw43_arch_poll() call

Result After 100ms:
- RX buffer overflows
- Packets dropped
- Client disconnects
```

### Task Context Switch

```
T=25ms:    WiFi Task running cyw43_arch_poll()
           │
           └─ USB interrupt fires (Serial data)
              │
              └─ Serial ISR calls vTaskNotifyGiveFromISR()
                 │
                 └─ Scheduler preempts WiFi (26 > 25)
                    │
                    └─ Serial Task runs
                       Process protocol message (~10ms)
                       │
                       └─ Serial Task blocks
                          │
                          └─ Scheduler resumes WiFi Task
                             Continues from where it left off in cyw43_arch_poll()

Result: WiFi had 25ms + 50ms = 75ms before next call
        (Well within 100ms timeout!)
```

## HTTP Server Configuration

### HTTP Handler Pattern

The lwIP HTTP server is **callback-based**, not blocking:

```c
// HTTP server processes requests in callbacks
// Your code provides the callback functions

// Register handlers during httpd_init()
// When request arrives:
//   1. lwIP parses HTTP headers
//   2. Calls your handler callback
//   3. Handler generates response
//   4. Response sent automatically
//   5. Connection closed
```

### Custom HTTP Handlers

To add custom endpoints, create callbacks:

```c
// In wifi_ap.c or separate http_handlers.c:

/**
 * GET /api/status
 * Returns current token state
 */
static const char status_response[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 85\r\n"
    "\r\n"
    "{\"state\": \"0x40\", \"encrypted\": true, \"session_valid\": true}";

/**
 * GET /api/config
 * Returns WiFi configuration
 */
static const char config_response[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 42\r\n"
    "\r\n"
    "{\"ssid\": \"MASTR-Token\", \"channel\": 80}";
```

### Adding Routes

With lwIP httpd, routes are typically defined in `fs/fs.c` or via callbacks:

```c
// Simple routing pattern
const struct fsdata_file file_index_html[] = {
    {name: "/", file: index_html, len: sizeof(index_html)},
    {name: "/api/status", file: api_status_json, len: sizeof(api_status_json)},
    {name: "/api/config", file: api_config_json, len: sizeof(api_config_json)},
};
```

For dynamic responses, use `http_set_ssi_handler()` or `http_set_cgi_handler()`.

## Troubleshooting Guide

### Issue: WiFi Not Starting

**Symptom**: `"Failed to start WiFi AP"` in output

**Diagnosis**:
```c
// Check if CYW43 initialized
if (cyw43_arch_wifi_set_ap(...) != 0) {
    return false;  // Returns here?
}
```

**Solution**:
1. Verify `wifi_ap_init()` was called before scheduler
2. Check pico_w board is selected: `cmake -DPICO_BOARD=pico_w`
3. Verify CMakeLists.txt has `pico_cyw43_arch_threadsafe_background`

### Issue: Clients Can't Connect

**Symptom**: "Can't see MASTR-Token in WiFi networks"

**Diagnosis**:
- CYW43 not broadcasting SSID
- WiFi background task not running

**Solution**:
```bash
# Check debug output for:
# "WiFi background task started" message

# If missing:
# - Verify xTaskCreate(wifi_background_task, ...)
# - Check priority is 25 (configMAX_PRIORITIES - 7)
```

### Issue: Clients Connect but No DHCP IP

**Symptom**: Client shows "Waiting for IP...", timeout

**Diagnosis**:
- DHCP server not started
- netif not initialized properly

**Solution**:
```c
// Verify order in wifi_ap_start():
netif_set_up(ap_netif);              // ← Must be BEFORE dhcp_server_init
dhcp_server_init(ap_netif, &gw, &mask);
```

### Issue: HTTP Requests Timeout

**Symptom**: `curl http://192.168.4.1/` hangs for 30s then timeout

**Diagnosis**:
- HTTP task not running
- HTTP server not initialized
- Socket not listening on correct interface

**Solution**:
```c
// Verify in wifi_ap_start():
httpd_init();  // Must be called

// Verify HTTP task created:
// xTaskCreate(http_server_task, ...)
```

### Issue: Serial Protocol Drops Messages

**Symptom**: Random "Missing ECDH response" errors

**Diagnosis**:
- WiFi task starving Serial task
- Serial task priority too low

**Solution**:
```c
// Check task priorities:
Serial:     configMAX_PRIORITIES - 6  = 26 ✓
WiFi-BG:    configMAX_PRIORITIES - 7  = 25 ✓ (lower)
HTTP:       10                         ✓ (much lower)

// Serial MUST be 26, not lower
```

### Issue: Memory Corruption / Crashes

**Symptom**: Random crashes, memory errors

**Diagnosis**:
- Task stack size too small
- Heap too fragmented

**Solution**:
```c
// Verify stack sizes:
Serial:     DEFAULT_STACK_SIZE (usually 2048) ✓
WiFi-BG:    2048                              ✓
HTTP:       4096 (might need more)            ✓
Watchdog:   1024                              ✓

// If crashes persist:
// Increase HTTP stack to 8192
```

## Performance Metrics

### CPU Usage Breakdown

```
Idle:               ~70%
WiFi Background:    ~15%
Serial Protocol:    ~10%
HTTP Server:        ~3%
Watchdog:           ~1%
Overhead:           ~1%
```

### Memory Usage

```
FreeRTOS Heap:      ~11KB (task stacks)
CYW43 Buffers:      ~32KB (fixed)
lwIP Pools:         ~16KB (dynamic)
Protocol State:     ~1KB
HTTP State:         ~2KB
Available RAM:      ~200KB (of 264KB total on Pico W)
```

### Latency Measurements

```
Serial Response:    5-50ms (USB protocol processing)
WiFi Latency:       ~100-200ms (typical WiFi frame timing)
HTTP Response:      200-500ms (including DHCP if new client)
Context Switch:     <1ms (FreeRTOS overhead)
```

## Configuration Options

### Change WiFi SSID

In `src/wifi_ap.c` or pass config:

```c
wifi_ap_config_t config = {
    .ssid = "My-Custom-AP",           // Max 32 chars
    .password = "SecurePassword123",   // Min 8 chars for WPA2
};
wifi_ap_start(&config);
```

### Change WiFi Channel

```c
// In wifi_ap_start():
cyw43_arch_wifi_set_ap(
    WIFI_AUTH_WPA2_PSK_SHA256,
    ssid, ssid_len,
    password, password_len,
    80  // ← Channel (1-13 valid, 80 = channel 1)
);
```

Valid channels: 1-13 (2.4 GHz)
- 80 = Channel 1 (2.412 GHz) - Default, best coverage
- 81 = Channel 2
- ...
- 92 = Channel 13

### Change DHCP IP Range

```c
IP4_ADDR(&gw, 10, 0, 0, 1);              // 10.0.0.1
IP4_ADDR(&mask, 255, 255, 255, 0);
// Now DHCP pool is 10.0.0.2-10.0.0.254
```

### Change HTTP Port

HTTP runs on port 80 by default (hardcoded in lwIP).
To use different port, would need to rebuild lwIP.

### Disable Encryption (Development Only)

```c
// In wifi_ap_start(), don't use WIFI_AUTH_WPA2:
cyw43_arch_wifi_set_ap(
    WIFI_AUTH_OPEN,  // ← No password
    ssid, ssid_len,
    password, password_len,
    80
);
```

## Advanced Debugging

### Enable WiFi Debug Output

In `include/pico/cyw43.h`:

```c
#define CYW43_DEBUG 1  // Enable debug prints
#define CYW43_DEBUG_LEVEL 3  // 0=off, 3=verbose
```

### Monitor Task Execution

In `src/main.c`:

```c
#include "FreeRTOS.h"
#include "task.h"

void print_task_stats() {
    UBaseType_t num_tasks = uxTaskGetNumberOfTasks();
    TaskStatus_t *task_stats = malloc(num_tasks * sizeof(TaskStatus_t));
    
    uxTaskGetSystemState(task_stats, num_tasks, NULL);
    
    for (int i = 0; i < num_tasks; i++) {
        printf("Task: %s, Priority: %ld, State: %ld\n",
            task_stats[i].pcTaskName,
            task_stats[i].uxCurrentPriority,
            task_stats[i].eCurrentState);
    }
    
    free(task_stats);
}

// Call from serial or HTTP handler:
// print_task_stats();
```

### Check WiFi State

```c
// Query CYW43 state
uint32_t wifi_status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_AP);
if (wifi_status == CYW43_LINK_UP) {
    printf("WiFi AP is UP\n");
} else if (wifi_status == CYW43_LINK_DOWN) {
    printf("WiFi AP is DOWN\n");
}
```

### Verify DHCP Assignments

```c
// In HTTP handler, get connected clients:
struct dhcp_server_state *server = dhcp_server_state;
for (int i = 0; i < DHCP_MAX_LEASES; i++) {
    if (server->leases[i].state == ASSIGNED) {
        printf("Client IP: %s\n", 
            ip4addr_ntoa(&server->leases[i].ip_addr));
    }
}
```

## Next Steps

- Implement HTTP handlers for your specific API
- Add OTA update endpoint over HTTP
- Configure web UI served from flash
- Implement client reconnection logic
