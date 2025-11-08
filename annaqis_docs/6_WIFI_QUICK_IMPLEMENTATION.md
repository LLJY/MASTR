# WiFi Quick Implementation Guide

Copy-paste code to add WiFi AP to your MASTR project. **Total time: 10 minutes.**

## Step 1: Update CMakeLists.txt

### Add WiFi Configuration (Top of File)

Find the section after `cmake_minimum_required()` and add:

```cmake
# WiFi Configuration for CYW43 (Pico W / Pico 2 W)
set(PICO_CYW43_ARCH_THREADSAFE_BACKGROUND ON)
set(PICO_LWIP_CONTRIB_FREERTOS 1)
```

### Update target_link_libraries

Find the existing `target_link_libraries()` section and replace it:

**Before:**
```cmake
target_link_libraries(pico_project_template
    pico_stdlib
    hardware_i2c
    cryptoauth
    pico_mbedtls
    FreeRTOS-Kernel-Heap4
    freertos_config)
```

**After:**
```cmake
target_link_libraries(pico_project_template
    pico_stdlib
    pico_cyw43_arch_threadsafe_background
    pico_lwip_http
    hardware_i2c
    cryptoauth
    pico_mbedtls
    FreeRTOS-Kernel-Heap4
    freertos_config)
```

### Update add_executable

Find the `add_executable()` section and add `src/wifi_ap.c`:

**Before:**
```cmake
add_executable(pico_project_template
    src/main.c
    src/serial.c
    src/protocol.c
    src/crypt.c
    src/hal/hal_pico_i2c.c
)
```

**After:**
```cmake
add_executable(pico_project_template
    src/main.c
    src/serial.c
    src/protocol.c
    src/crypt.c
    src/wifi_ap.c
    src/hal/hal_pico_i2c.c
)
```

## Step 2: Create WiFi Header File

Create file: `include/wifi_ap.h`

```c
#ifndef WIFI_AP_H
#define WIFI_AP_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char ssid[32];
    char password[64];
    uint32_t ip_address;
    bool is_running;
} wifi_ap_config_t;

// Initialize WiFi hardware (call before FreeRTOS starts)
bool wifi_ap_init(void);

// Start WiFi AP
bool wifi_ap_start(const wifi_ap_config_t *config);

// Stop WiFi AP
void wifi_ap_stop(void);

// Get config
wifi_ap_config_t* wifi_ap_get_config(void);

// FreeRTOS task functions
void wifi_background_task(void *params);
void http_server_task(void *params);

#endif  // WIFI_AP_H
```

## Step 3: Create WiFi Implementation

Create file: `src/wifi_ap.c`

```c
#include "wifi_ap.h"
#include "logger.h"
#include <string.h>
#include <stdlib.h>

#ifndef UNIT_TEST
#include "pico/cyw43_arch.h"
#include "lwip/netif.h"
#include "lwip/dhcp_server.h"
#include "lwip/ip4_addr.h"
#include "lwip/init.h"
#include "lwip/httpd.h"
#include "FreeRTOS.h"
#include "task.h"
#else
typedef void netif_t;
#endif

static wifi_ap_config_t wifi_config = {
    .ssid = "MASTR-Token",
    .password = "MastrToken123",
    .ip_address = 0xC0A80401,
    .is_running = false
};

/**
 * Initialize WiFi hardware (call before FreeRTOS starts)
 */
bool wifi_ap_init(void) {
    #ifndef UNIT_TEST
    if (cyw43_arch_init()) {
        print_error("CYW43 init failed\n");
        return false;
    }
    
    cyw43_arch_enable_ap_mode();
    print_info("WiFi hardware initialized (AP mode ready)\n");
    return true;
    #else
    return true;
    #endif
}

/**
 * Start WiFi AP with configuration
 */
bool wifi_ap_start(const wifi_ap_config_t *config) {
    if (config == NULL) {
        return false;
    }
    
    memcpy(&wifi_config, config, sizeof(wifi_ap_config_t));
    
    #ifndef UNIT_TEST
    // Start AP with WPA2 security
    if (cyw43_arch_wifi_set_ap(WIFI_AUTH_WPA2_PSK_SHA256,
                               (const uint8_t *)wifi_config.ssid,
                               strlen(wifi_config.ssid),
                               (const uint8_t *)wifi_config.password,
                               strlen(wifi_config.password),
                               80)) {
        print_error("Failed to start WiFi AP\n");
        return false;
    }
    
    // Configure DHCP server
    ip4_addr_t gw, mask;
    IP4_ADDR(&gw, 192, 168, 4, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    
    struct netif *ap_netif = &cyw43_state.netif[1];
    
    netif_set_ipaddr(ap_netif, &gw);
    netif_set_netmask(ap_netif, &mask);
    netif_set_gw(ap_netif, &gw);
    netif_set_up(ap_netif);
    
    // Start DHCP server
    if (dhcp_server_init(ap_netif, &gw, &mask)) {
        print_error("Failed to start DHCP server\n");
        return false;
    }
    
    // Start HTTP server
    httpd_init();
    
    wifi_config.is_running = true;
    print_info("WiFi AP started: %s (192.168.4.1)\n", wifi_config.ssid);
    return true;
    #else
    wifi_config.is_running = true;
    return true;
    #endif
}

/**
 * Stop WiFi AP
 */
void wifi_ap_stop(void) {
    #ifndef UNIT_TEST
    cyw43_arch_disable_ap_mode();
    wifi_config.is_running = false;
    print_info("WiFi AP stopped\n");
    #endif
}

/**
 * Get current WiFi configuration
 */
wifi_ap_config_t* wifi_ap_get_config(void) {
    return &wifi_config;
}

/**
 * WiFi background task (runs every 50ms)
 * This is required for CYW43 driver to process events
 */
void wifi_background_task(void *params) {
    (void)params;
    print_info("WiFi background task started\n");
    
    while (true) {
        // Run every 50ms
        vTaskDelay(pdMS_TO_TICKS(50));
        
        #ifndef UNIT_TEST
        // Let CYW43 driver process WiFi events
        cyw43_arch_poll();
        
        // lwIP timers are called internally
        #endif
    }
}

/**
 * HTTP server task
 * Listens for and handles HTTP requests
 */
void http_server_task(void *params) {
    (void)params;
    print_info("HTTP server task started\n");
    
    #ifndef UNIT_TEST
    // lwIP httpd is running (initialized in wifi_ap_start)
    // Just keep task alive
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    #else
    vTaskDelete(NULL);
    #endif
}
```

## Step 4: Update main.c

### Add Include

At top of `main.c`:

```c
#include "wifi_ap.h"
```

### WiFi Hardware Init (Before Scheduler)

In `main()` function, find where you call `crypt_init()` and `serial_init()`. Add after those:

```c
    // Initialize WiFi hardware (must be BEFORE FreeRTOS starts)
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    if (!wifi_ap_init()) {
        print_error("WARNING: WiFi init failed\n");
    }
    #endif
```

### Create WiFi Tasks (Before Scheduler)

Find where you create `serial_task` and `watchdog_task`. Add these after:

```c
    // WiFi Background Task (priority 25, runs every 50ms)
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    TaskHandle_t wifi_bg_handle;
    xTaskCreate(
        wifi_background_task,
        "WiFi-BG",
        2048,
        NULL,
        configMAX_PRIORITIES - 7,  // Priority 25
        &wifi_bg_handle
    );
    #endif
    
    // HTTP Server Task (priority 10, handles API requests)
    TaskHandle_t http_handle;
    xTaskCreate(
        http_server_task,
        "HTTP-Server",
        2048,
        NULL,
        10,
        &http_handle
    );
    
    // WiFi Init Task (starts AP after FreeRTOS running)
    TaskHandle_t wifi_init_handle;
    xTaskCreate(
        wifi_init_task,
        "WiFi-Init",
        2048,
        NULL,
        5,
        &wifi_init_handle
    );
```

### WiFi Init Task Function

Add this function to `main.c` (before `main()`):

```c
void wifi_init_task(void *params) {
    (void)params;
    
    // Wait for system stabilization
    vTaskDelay(pdMS_TO_TICKS(500));
    
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "MastrToken123",
    };
    
    if (wifi_ap_start(&config)) {
        print_info("WiFi AP started successfully\n");
    } else {
        print_error("Failed to start WiFi AP\n");
    }
    #endif
    
    // Task complete, delete self
    vTaskDelete(NULL);
}
```

## Step 5: Build & Test

### Build

```bash
cd build
cmake -DPICO_BOARD=pico_w ..
make -j4
```

### Monitor Output

Connect serial (115200 baud):

```bash
minicom -D /dev/ttyACM0 -b 115200
```

Expected output:

```
WiFi hardware initialized (AP mode ready)
WiFi background task started
HTTP server task started
WiFi AP started: MASTR-Token (192.168.4.1)
```

### Test WiFi Connection

```bash
# Scan for WiFi networks - should see "MASTR-Token"
# Connect with password: MastrToken123
# DHCP will assign IP from 192.168.4.x range
```

### Test HTTP (optional)

```bash
# From connected client:
curl http://192.168.4.1/
```

## File Checklist

✅ Modified: `CMakeLists.txt` (3 changes)  
✅ Created: `include/wifi_ap.h`  
✅ Created: `src/wifi_ap.c`  
✅ Modified: `src/main.c` (4 sections)  

**Total lines added**: ~250  
**Total time**: 10-15 minutes  

## What This Gives You

- ✅ WiFi AP running on fixed IP: 192.168.4.1
- ✅ DHCP server assigning IPs to clients
- ✅ HTTP server listening on port 80
- ✅ Serial protocol still working (higher priority)
- ✅ All tasks properly scheduled by FreeRTOS

## Next Steps

For HTTP API endpoints, see `7_WIFI_DETAILED_GUIDE.md`  
For troubleshooting, see `8_WIFI_IMPLEMENTATION_CHECKLIST.md`
