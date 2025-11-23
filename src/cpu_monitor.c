/**
 * CPU Utilization Monitoring
 * 
 * Tracks idle task execution time to calculate real CPU utilization.
 * Uses FreeRTOS idle hook to increment idle tick counter.
 */

#include <stdint.h>
#include <stddef.h>
#include "FreeRTOS.h"
#include "task.h"
#include "cpu_monitor.h"
#include <stdint.h>
#include <string.h>
#include <string.h>
#include "pico/time.h"
#include "serial.h"


// Tick-based idle accounting reinstated for fallback stability.
volatile uint32_t g_idleTicks = 0;
void vApplicationIdleHook(void) {
    static uint32_t lastTick = 0;
    uint32_t now = xTaskGetTickCount();
    if (now != lastTick) {
        g_idleTicks++;
        lastTick = now;
    }
}

// Cached CPU percentage (updated by background task, read by HTTP handlers)
// Volatile to ensure thread-safe reads from HTTP handler context
static volatile uint32_t g_cached_cpu_percent = 0;

// Internal function: Calculate CPU usage percent (integer 0-100) using FreeRTOS run-time stats.
// Accurate path: sum per-task run time counters and derive busy = total - idle.
// Uses a minimum delta window to avoid noisy tiny samples.
// WARNING: Calls uxTaskGetSystemState() which suspends scheduler - do NOT call from HTTP handlers!
static uint32_t cpu_calculate_percent(void)
{
    #define CPU_MON_MAX_TASKS 48
    static TaskStatus_t stats_buf[CPU_MON_MAX_TASKS];
    static uint32_t last_total = 0;
    static uint32_t last_idle = 0;
    static uint32_t acc_total = 0;
    static uint32_t acc_idle  = 0;
    static uint32_t last_percent = 0;

    // Return last known if scheduler not running
    if (xTaskGetSchedulerState() != taskSCHEDULER_RUNNING) {
        return last_percent;
    }

    UBaseType_t numTasks = uxTaskGetNumberOfTasks();
    if (numTasks < 2) { // Need at least Idle + one other
        return last_percent;
    }

    UBaseType_t cap = (numTasks > CPU_MON_MAX_TASKS) ? CPU_MON_MAX_TASKS : numTasks;
    uint32_t ignoredTotalTime = 0;
    UBaseType_t got = uxTaskGetSystemState(stats_buf, cap, &ignoredTotalTime);
    if (got == 0) {
        return last_percent;
    }

    uint32_t sumAll = 0;
    uint32_t sumIdle = 0;
    for (UBaseType_t i = 0; i < got; i++) {
        sumAll += stats_buf[i].ulRunTimeCounter;
        if (stats_buf[i].uxCurrentPriority == 0 && stats_buf[i].pcTaskName) {
            const char *nm = stats_buf[i].pcTaskName;
            if ((nm[0]=='I' || nm[0]=='i') && (strncmp(nm, "IDLE", 4)==0 || strncmp(nm,"Idle",4)==0 || strncmp(nm,"idle",4)==0)) {
                sumIdle += stats_buf[i].ulRunTimeCounter;
            }
        }
    }

    if (last_total == 0) { // establish baseline
        last_total = sumAll;
        last_idle  = sumIdle;
        return last_percent;
    }

    uint32_t dTotal = sumAll - last_total;
    uint32_t dIdle  = sumIdle - last_idle;
    last_total = sumAll;
    last_idle  = sumIdle;

    if (dTotal == 0 || dIdle > dTotal) {
        return last_percent;
    }

    // Accumulate to reach ~100ms window at 10kHz runtime counter (threshold = 1000 ticks)
    acc_total += dTotal;
    acc_idle  += dIdle;
    const uint32_t MIN_RT_DELTA = 1000; // ~100ms
    if (acc_total < MIN_RT_DELTA) {
        return last_percent; // wait for sufficient window
    }

    dTotal = acc_total;
    dIdle  = acc_idle;
    acc_total = 0;
    acc_idle  = 0;

    if (dIdle > dTotal) {
        return last_percent;
    }

    uint32_t busy = dTotal - dIdle;
    uint32_t percent = (busy * 100U + (dTotal / 2U)) / dTotal; // rounded
    last_percent = percent;
    return percent;
}

// Public API: Get cached CPU percentage (safe to call from any context)
// Returns cached value updated by background task, avoiding scheduler suspension in HTTP context
uint32_t cpu_get_percent(void) {
    return g_cached_cpu_percent;
}

// Background task: Updates cached CPU percentage every 500ms
// This prevents calling uxTaskGetSystemState() from HTTP handler context (which can deadlock lwIP)
void cpu_monitor_task(void *params) {
    (void)params;

    while (true) {
        // Calculate CPU percentage in a safe task context (not from HTTP callback)
        uint32_t new_percent = cpu_calculate_percent();

        // Update cached value (volatile ensures atomic write)
        g_cached_cpu_percent = new_percent;

        // Update every 500ms
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

// Provide the runtime counter for FreeRTOS stats without including Pico headers in FreeRTOSConfig.h
uint32_t freertos_runtime_counter_get(void)
{
    // Scale microsecond hardware timer to ~10kHz resolution (100 microseconds per tick)
    // Improves stability of short-window measurements and extends wrap period.
    return (uint32_t)(time_us_64() / 100ULL);
}
