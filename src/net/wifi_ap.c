#include "wifi_ap.h"
#include "serial.h"
#include "ap/ap_manager.h"
#include <string.h>
#include <stdlib.h>

#ifndef UNIT_TEST
#include "FreeRTOS.h"
#include "task.h"
#endif

static wifi_ap_config_t wifi_config = {
    .ssid = "MASTR-Token",
    .password = "MastrToken123",
    .ip_address = 0xC0A80401,  // 192.168.4.1
    .is_running = false
};

/**
 * Initialize WiFi hardware (lightweight - just prepares config)
 * Actual CYW43 initialization happens in wifi_ap_init_task after FreeRTOS starts
 */
bool wifi_ap_init(void) {
    // Just mark that we're ready to initialize WiFi
    // The actual cyw43_arch_init() must happen in a FreeRTOS task
    print_dbg("WiFi subsystem ready for initialization\n");
    return true;
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
    if (start_access_point(wifi_config.ssid, wifi_config.password) != 0) {
        print_dbg("ERROR: Failed to start WiFi AP\n");
        return false;
    }

    wifi_config.is_running = true;
    print_dbg("WiFi AP started: SSID=%s (192.168.4.1)\n", wifi_config.ssid);
    #endif

    return true;
}

/**
 * Stop WiFi AP
 */
void wifi_ap_stop(void) {
    #ifndef UNIT_TEST
    stop_access_point();
    wifi_config.is_running = false;
    print_dbg("WiFi AP stopped\n");
    #endif
}

/**
 * Get WiFi configuration
 */
wifi_ap_config_t* wifi_ap_get_config(void) {
    return &wifi_config;
}

/**
 * WiFi background task (runs frequently to process network events)
 * 
 * This task is CRITICAL for CYW43 driver and lwIP stack operation.
 * It must run regularly (every 50-100ms) to:
 * - Process WiFi driver events
 * - Handle network timeouts
 * - Manage DHCP state
 * - Process incoming packets
 * 
 * Priority: 25 (just below serial task at 26)
 * Sleep interval: 50ms (allows lwIP to process events regularly)
 */
void wifi_background_task(void *params) {
    (void)params;
    
    print_dbg("WiFi background task started (priority 25, 50ms interval)\n");
    
    while (true) {
        #ifndef UNIT_TEST
        // Sleep briefly to allow CYW43 driver and lwIP to process events
        // CYW43_ARCH_THREADSAFE_BACKGROUND automatically handles the background work
        // This sleep allows task switching and prevents blocking
        vTaskDelay(pdMS_TO_TICKS(50));
        #else
        vTaskDelay(pdMS_TO_TICKS(50));
        #endif
    }
}

/**
 * HTTP server task (FreeRTOS task function)
 * 
 * Handles HTTP server monitoring and API request processing
 * 
 * Recommended Priority: 10
 * Recommended Stack: 2048 bytes
 * 
 * @param params Unused task parameters
 */
void http_server_task(void *params) {
    (void)params;
    
    print_dbg("HTTP server task started (priority 5, 100ms interval)\n");
    
    // Only run if AP is configured
    if (!wifi_config.is_running) {
        print_dbg("HTTP server: AP not running, task exiting\n");
        vTaskDelete(NULL);  // Delete self
        return;
    }
    
    while (true) {
        #ifndef UNIT_TEST
        // lwIP httpd is interrupt/callback-driven through recv callbacks
        // This task primarily monitors server health and manages long-running requests
        vTaskDelay(pdMS_TO_TICKS(100));
        #else
        vTaskDelay(pdMS_TO_TICKS(100));
        #endif
    }
}

/**
 * WiFi AP initialization task
 * 
 * Starts the WiFi AP after the scheduler is running.
 * This runs once and then exits.
 * 
 * @param params Pointer to wifi_ap_config_t (or NULL to use default)
 */
void wifi_ap_init_task(void *params) {
    print_dbg("WiFi AP init task started - waiting 60 seconds for scheduler/provisioning stability\n");
    

    vTaskDelay(pdMS_TO_TICKS(100));
    
    print_dbg("WiFi AP init task: 60 second delay complete, starting initialization\n");
    
    wifi_ap_config_t *config = (wifi_ap_config_t *)params;
    if (config == NULL) {
        config = &wifi_config;
    }
    
    if (wifi_ap_start(config)) {
        print_dbg("WiFi AP initialization successful\n");
    } else {
        print_dbg("ERROR: WiFi AP initialization failed\n");
    }
    
    // Task completes after starting AP
    vTaskDelete(NULL);
}
