#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// Tick-based idle counter used by the simple CPU endpoint path
extern volatile uint32_t g_idleTicks;

// Returns CPU utilization percent over the interval since the last call.
// Uses FreeRTOS run-time stats when available; otherwise may return 0.
uint32_t cpu_get_percent(void);

#ifdef __cplusplus
}
#endif
