#ifndef SERIAL_H
#define SERIAL_H

#include <stdint.h>

void process_serial_data();

static void process_complete_frame();

void send_message(uint8_t msg_type, uint8_t *payload, uint16_t len);

void send_shutdown_signal();
#endif