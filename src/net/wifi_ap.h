#ifndef WIFI_AP_H
#define WIFI_AP_H

#include <stdbool.h>
#include <stdint.h>

/**
 * WiFi AP Configuration Structure
 */
typedef struct {
    const char *ssid;           // WiFi SSID (e.g., "MASTR-Token")
    const char *password;       // WiFi password (must be >= 8 chars for WPA2)
    uint32_t ip_address;        // IP address in network byte order (e.g., 0xC0A80401 for 192.168.4.1)
    bool is_running;            // Is AP currently running
} wifi_ap_config_t;

/**
 * Initialize WiFi hardware (CYW43 driver)
 * 
 * MUST be called BEFORE FreeRTOS scheduler starts
 * Sets up:
 * - CYW43 driver
 * - lwIP stack
 * - AP mode capability
 * 
 * @return true if successful, false on error
 */
bool wifi_ap_init(void);

/**
 * Start WiFi Access Point with configuration
 * 
 * Can be called at any time after wifi_ap_init() succeeds
 * Sets up:
 * - WiFi AP with SSID and WPA2-PSK security
 * - DHCP server (192.168.4.0/24)
 * - HTTP server on port 80
 * - API endpoints (/api/ping, /api/info)
 * 
 * @param config Pointer to wifi_ap_config_t with desired SSID/password
 * @return true if successful, false on error
 */
bool wifi_ap_start(const wifi_ap_config_t *config);

/**
 * Stop WiFi Access Point
 * 
 * Shuts down:
 * - WiFi driver
 * - Network interfaces
 * - HTTP server
 * 
 * @return none
 */
void wifi_ap_stop(void);

/**
 * Get current WiFi configuration
 * 
 * @return Pointer to current wifi_ap_config_t
 */
wifi_ap_config_t* wifi_ap_get_config(void);

/**
 * WiFi background task (FreeRTOS task function)
 * 
 * CRITICAL: This task must run regularly (every 50-100ms) for:
 * - CYW43 driver event processing
 * - lwIP stack operation
 * - DHCP server maintenance
 * - Incoming packet handling
 * 
 * Recommended Priority: 25 (just below serial task at 26)
 * Recommended Stack: 2048 bytes
 * 
 * @param params Unused task parameters
 */
void wifi_background_task(void *params);

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
void http_server_task(void *params);

/**
 * WiFi AP initialization task (FreeRTOS task function)
 * 
 * Starts the WiFi AP after the scheduler is running.
 * This runs once and then exits.
 * 
 * @param params Pointer to wifi_ap_config_t (or NULL to use default)
 */
void wifi_ap_init_task(void *params);

#endif // WIFI_AP_H
