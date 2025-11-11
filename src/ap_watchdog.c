#include "ap_watchdog.h"
#include "hardware/watchdog.h"
#include "pico/stdlib.h"
#include "FreeRTOS.h"
#include "task.h"
#include "wifi_ap.h"

// Watchdog timeout in milliseconds (2 seconds)
#define AP_WATCHDOG_TIMEOUT_MS 2000

// How often to check AP task health
#define AP_MONITOR_PERIOD_MS 500

// Maximum time AP can be blocked/unresponsive
#define AP_MAX_BLOCK_TIME_MS 1000

static TaskHandle_t ap_task = NULL;
static TaskHandle_t monitor_task = NULL;
static volatile bool ap_is_alive = false;

static void ap_monitor_task(void *params) {
    (void)params;
    TickType_t last_wake_time;
    
    // Initialize last wake time
    last_wake_time = xTaskGetTickCount();
    
    while(1) {
        // Wait for the next check period
        vTaskDelayUntil(&last_wake_time, pdMS_TO_TICKS(AP_MONITOR_PERIOD_MS));
        
        if (ap_is_alive) {
            // AP reported alive, reset flag and kick watchdog
            ap_is_alive = false;
            watchdog_update();
        } else {
            // AP failed to report - trigger reset
            ap_watchdog_reset_ap();
        }
    }
}

void ap_watchdog_init(TaskHandle_t ap_task_handle) {
    if (ap_task_handle == NULL) {
        return;
    }
    
    // Store AP task handle
    ap_task = ap_task_handle;
    
    // Initialize hardware watchdog
    watchdog_enable(AP_WATCHDOG_TIMEOUT_MS, true);
    
    // Create monitoring task
    xTaskCreate(ap_monitor_task,
                "APWdog",
                configMINIMAL_STACK_SIZE,
                NULL,
                configMAX_PRIORITIES - 1,
                &monitor_task);
}

void ap_watchdog_notify_alive(void) {
    // Called periodically by AP task to indicate health
    ap_is_alive = true;
}

void ap_watchdog_reset_ap(void) {
    // Delete AP task
    if (ap_task != NULL) {
        vTaskDelete(ap_task);
        ap_task = NULL;
    }
    
    // Stop wifi hardware
    wifi_ap_stop();
    
    // Brief delay to ensure cleanup
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // Restart wifi hardware and task
    TaskHandle_t new_ap_task = NULL;
    xTaskCreate(wifi_ap_init_task,
                "WiFiAP",
                2048,
                NULL,
                5,
                &new_ap_task);
                
    // Update stored task handle
    ap_task = new_ap_task;
}