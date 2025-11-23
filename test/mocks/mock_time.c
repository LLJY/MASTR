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

// NOTE: vTaskDelay is now in mock_pico_sdk.c to avoid duplicate definitions