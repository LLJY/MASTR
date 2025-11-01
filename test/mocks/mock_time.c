#include "mock_time.h"

// Global mock time state
static uint64_t mock_current_time_us = 0;

void mock_time_reset(void) {
    mock_current_time_us = 0;
}

void mock_time_set(uint64_t time_us) {
    mock_current_time_us = time_us;
}

void mock_time_advance(uint64_t delta_ms) {
    mock_current_time_us += (delta_ms * 1000);  // Convert ms to us
}

uint64_t mock_time_get(void) {
    return mock_current_time_us;
}

// Override Pico SDK time function for unit tests
uint64_t time_us_64(void) {
    return mock_current_time_us;
}

// Mock FreeRTOS delay (does nothing in tests, but advances time)
void vTaskDelay(uint32_t ticks) {
    // In tests, 1 tick = 1ms for simplicity
    mock_current_time_us += (ticks * 1000);
}

// Mock FreeRTOS delay helper
uint32_t pdMS_TO_TICKS(uint32_t ms) {
    return ms;  // 1:1 mapping for tests
}