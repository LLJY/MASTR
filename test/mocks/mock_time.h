#ifndef MOCK_TIME_H
#define MOCK_TIME_H

#include <stdint.h>

// Mock time control functions
void mock_time_reset(void);
void mock_time_set(uint64_t time_us);
void mock_time_advance(uint64_t delta_ms);
uint64_t mock_time_get(void);

// Override Pico SDK time function
uint64_t time_us_64(void);

#endif // MOCK_TIME_H