#ifndef SERIAL_H
#define SERIAL_H

#include <stdint.h>

#ifndef UNIT_TEST
#include "FreeRTOS.h"
#include "task.h"
#else
// For unit tests, define TaskHandle_t as void pointer
typedef void* TaskHandle_t;
#endif

// Initialize serial with interrupt-based reception
// Pass the task handle for direct task notifications
void serial_init(TaskHandle_t task_handle);

// Process received data (called from interrupt or task)
void serial_process_data();

static void serial_process_complete_frame();

void send_message(uint8_t msg_type, uint8_t *payload, uint16_t len);

void send_shutdown_signal();

// Debug print function that sends via DEBUG_MSG protocol
// Safe to call even when DEBUG is not defined
void print_dbg(const char *format, ...);

#ifdef UNIT_TEST
// Test helper to inject data into rx_buffer for unit tests
void test_inject_rx_data(const uint8_t* data, uint16_t len);
#endif

#endif // SERIAL_H