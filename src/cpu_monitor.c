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
// Forward declaration for cpu_get_percent (optional header could be added later)


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

// Return CPU usage percent (integer 0-100) using FreeRTOS run-time stats.
// Accurate path: sum per-task run time counters and derive busy = total - idle.
// Uses a minimum delta window to avoid noisy tiny samples.
uint32_t cpu_get_percent(void)
{
    #define CPU_MON_MAX_TASKS 48
    static TaskStatus_t stats_buf[CPU_MON_MAX_TASKS];
    static uint32_t last_total = 0;
    static uint32_t last_idle = 0;
    static uint32_t acc_total = 0;
    static uint32_t acc_idle  = 0;
    static uint32_t last_percent = 0;

    // If scheduler not running yet, just return last cached percent.
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

// Provide the runtime counter for FreeRTOS stats without including Pico headers in FreeRTOSConfig.h
uint32_t freertos_runtime_counter_get(void)
{
    // Scale microsecond hardware timer to ~10kHz resolution (100 microseconds per tick)
    // Improves stability of short-window measurements and extends wrap period.
    return (uint32_t)(time_us_64() / 100ULL);
}
