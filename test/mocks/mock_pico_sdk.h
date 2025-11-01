#ifndef MOCK_PICO_SDK_H
#define MOCK_PICO_SDK_H

#include <stdint.h>
#include <stdbool.h>

// --- Mock FreeRTOS Types ---
typedef void* TaskHandle_t;

#include "protocol.h" // <-- Include after defining TaskHandle_t

// --- Mocked Constants ---
#define PICO_ERROR_TIMEOUT (-1)

// --- Test Helper/Spy Prototypes ---
void reset_mocks(void);
void load_mock_buffer(const uint8_t* data, uint16_t len);
const uint8_t* get_mock_buffer(void);
uint16_t get_mock_buffer_len(void);
bool was_handler_called(void);
message_type_t get_last_msg_type(void);
uint16_t get_last_len(void);
void get_last_payload(uint8_t* buffer);
bool was_shutdown_signal_called(void);


// From pico/stdlib.h
int getchar_timeout_us(uint32_t timeout_us);

// From tusb.h (TinyUSB)
void tud_cdc_write_char(char c);
uint32_t tud_cdc_write_available(void);
void tud_cdc_write_flush(void);

#endif // MOCK_PICO_SDK_H