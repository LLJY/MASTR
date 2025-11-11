#ifndef AP_WATCHDOG_H
#define AP_WATCHDOG_H

#include <stdbool.h>
#include <stdint.h>
#include "FreeRTOS.h"
#include "task.h"

/**
 * Initialize AP watchdog 
 * Sets up hardware watchdog and monitoring for the AP task
 * 
 * @param ap_task_handle Handle to the AP task to monitor
 */
void ap_watchdog_init(TaskHandle_t ap_task_handle);

/**
 * Should be called periodically from the AP task to indicate health
 */
void ap_watchdog_notify_alive(void);

/**
 * Reset the AP task and reinitialize
 * Called automatically by watchdog on timeout
 */
void ap_watchdog_reset_ap(void);

#endif /* AP_WATCHDOG_H */