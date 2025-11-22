#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// Tick-based idle counter used by the simple CPU endpoint path
extern volatile uint32_t g_idleTicks;

// Returns CPU utilization percent (0-100)
// Returns cached value updated by background task (safe to call from any context)
uint32_t cpu_get_percent(void);

// CPU monitoring background task (updates cached CPU percentage every 500ms)
// Start this task from main() to enable CPU monitoring
void cpu_monitor_task(void *params);

#ifdef __cplusplus
}
#endif
