#ifndef SERIAL_H
#define SERIAL_H

#include <stdint.h>

#ifndef UNIT_TEST
#include "FreeRTOS.h"
#include "task.h"
#endif

// Initialize serial with interrupt-based reception
// Pass the task handle for direct task notifications
#ifndef UNIT_TEST
void serial_init(TaskHandle_t task_handle);
#else
void serial_init(TaskHandle_t task_handle);
#endif

// Process received data (called from interrupt or task)
void process_serial_data();

static void process_complete_frame();

void send_message(uint8_t msg_type, uint8_t *payload, uint16_t len);

void send_shutdown_signal();

// Debug print function that sends via DEBUG_MSG protocol
// Safe to call even when DEBUG is not defined
void print_dbg(const char *format, ...);

#endif // SERIAL_H