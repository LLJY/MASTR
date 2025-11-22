#include "wifi_ap.h"
#include "serial.h"
#include "ap_manager.h"
#include <string.h>
#include <stdlib.h>

#ifndef UNIT_TEST
#include "FreeRTOS.h"
#include "task.h"
#endif

static char wifi_pass_storage[65] = "";
static wifi_ap_config_t wifi_config = {
    .ssid = "MASTR-Token",
    .password = wifi_pass_storage,
    .ip_address = 0xC0A80401,
    .is_running = false
};

/*******************************************************************************
 * @brief Prepare WiFi subsystem configuration (pre-FreeRTOS).
 * @return true on success.
 ******************************************************************************/
bool wifi_ap_init(void) {
    print_dbg("WiFi subsystem ready for initialization\n");
    return true;
}

/*******************************************************************************
 * @brief Start the WiFi AP with the given configuration.
 * @param config Configuration to apply.
 * @return true on success, false on failure.
 ******************************************************************************/
bool wifi_ap_start(const wifi_ap_config_t *config) {
    if (config == NULL) {
        return false;
    }
    wifi_config.ssid = config->ssid;
    if (config->password) {
        size_t len = strlen(config->password);
        if (len >= sizeof(wifi_pass_storage)) len = sizeof(wifi_pass_storage) - 1;
        memcpy(wifi_pass_storage, config->password, len);
        wifi_pass_storage[len] = '\0';
    } else {
        wifi_pass_storage[0] = '\0';
    }
    wifi_config.password = wifi_pass_storage;
    wifi_config.ip_address = config->ip_address;
    wifi_config.is_running = false;

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

/*******************************************************************************
 * @brief Stop the WiFi AP.
 * @return void
 ******************************************************************************/
void wifi_ap_stop(void) {
    #ifndef UNIT_TEST
    stop_access_point();
    wifi_config.is_running = false;
    print_dbg("WiFi AP stopped\n");
    #endif
}

/*******************************************************************************
 * @brief Get the current WiFi AP configuration.
 * @return Pointer to configuration.
 ******************************************************************************/
wifi_ap_config_t* wifi_ap_get_config(void) {
    return &wifi_config;
}

/*******************************************************************************
 * @brief Rotate AP password and apply live without full restart.
 * @param new_pass New passphrase.
 * @return true on success, false on failure.
 ******************************************************************************/
bool wifi_ap_rotate_password(const char *new_pass) {
    if (new_pass == NULL) return false;
    size_t len = strlen(new_pass);
    if (len >= sizeof(wifi_pass_storage)) len = sizeof(wifi_pass_storage) - 1;
    memcpy(wifi_pass_storage, new_pass, len);
    wifi_pass_storage[len] = '\0';
    wifi_config.password = wifi_pass_storage;

    if (reconfigure_access_point(wifi_config.ssid, wifi_config.password) != 0) {
        print_dbg("ERROR: AP reconfiguration failed, attempting OPEN fallback\n");
        wifi_pass_storage[0] = '\0';
        wifi_config.password = wifi_pass_storage;
        reconfigure_access_point(wifi_config.ssid, "");
        return false;
    }
    wifi_config.is_running = true;
    return true;
}

/*******************************************************************************
 * @brief FreeRTOS background task for WiFi driver upkeep.
 * @param params Unused task parameter.
 * @return void
 ******************************************************************************/
void wifi_background_task(void *params) {
    (void)params;
    
    print_dbg("WiFi background task started (priority 25, 50ms interval)\n");
    
    while (true) {
        #ifndef UNIT_TEST
        vTaskDelay(pdMS_TO_TICKS(50));
        #else
        vTaskDelay(pdMS_TO_TICKS(50));
        #endif
    }
}

/*******************************************************************************
 * @brief FreeRTOS task shell for HTTP server monitoring.
 * @param params Unused task parameter.
 * @return void
 ******************************************************************************/
void http_server_task(void *params) {
    (void)params;
    
    print_dbg("HTTP server task started (priority 5, 100ms interval)\n");
    
    if (!wifi_config.is_running) {
        print_dbg("HTTP server: AP not running, task exiting\n");
        vTaskDelete(NULL);
        return;
    }
    
    while (true) {
        #ifndef UNIT_TEST
        vTaskDelay(pdMS_TO_TICKS(100));
        #else
        vTaskDelay(pdMS_TO_TICKS(100));
        #endif
    }
}

/*******************************************************************************
 * @brief FreeRTOS task to start the WiFi AP once scheduler is running.
 * @param params Optional wifi_ap_config_t pointer.
 * @return void
 ******************************************************************************/
void wifi_ap_init_task(void *params) {
    print_dbg("WiFi AP init task started\n");
    
    wifi_ap_config_t *config = (wifi_ap_config_t *)params;
    if (config == NULL) {
        config = &wifi_config;
    }
    
    if (wifi_ap_start(config)) {
        print_dbg("WiFi AP initialization successful\n");
    } else {
        print_dbg("ERROR: WiFi AP initialization failed\n");
    }
    
    vTaskDelete(NULL);
}

/*******************************************************************************
 * @brief Report whether the WiFi AP is active.
 * @return true if running and healthy.
 ******************************************************************************/
bool wifi_ap_is_active(void) {
    #ifndef UNIT_TEST
    if (!wifi_config.is_running) {
        return false;
    }
    
    return true;
    #else
    return wifi_config.is_running;
    #endif
}

/*******************************************************************************
 * @brief Restart the WiFi AP using current configuration.
 * @return true on success, false on failure.
 ******************************************************************************/
bool wifi_ap_restart(void) {
    print_dbg("WiFi AP: Attempting restart...\n");
    
    wifi_ap_stop();
    
    #ifndef UNIT_TEST
    vTaskDelay(pdMS_TO_TICKS(1000));
    #endif
    
    bool success = wifi_ap_start(&wifi_config);
    if (success) {
        print_dbg("WiFi AP: Restart successful\n");
    } else {
        print_dbg("WiFi AP: Restart failed\n");
    }
    
    return success;
}
