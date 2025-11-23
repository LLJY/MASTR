#include "mock_pico_sdk.h"
#include "constants.h"
#include "protocol.h"
#include "serial.h"
#include "crypto.h"
#include "unity.h"
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>

// --- Mock Serial Wire ---
static uint8_t mock_serial_buffer[1024];
static uint16_t write_idx = 0;
static uint16_t read_idx = 0;

// --- Test Spy Variables ---
static bool mock_handle_validated_message_called = false;
static message_type_t last_msg_type;
static uint8_t last_payload[MAX_PAYLOAD_SIZE];
static uint16_t last_len;

static bool mock_send_shutdown_signal_called = false;

// ========================================================================
// ## Test Helper Functions (NEW section)
// ========================================================================

void reset_mocks(void) {
    memset(mock_serial_buffer, 0, sizeof(mock_serial_buffer));
    write_idx = 0;
    read_idx = 0;

    mock_handle_validated_message_called = false;
    memset(last_payload, 0, sizeof(last_payload));
    last_len = 0;
    last_msg_type = 0;
    mock_send_shutdown_signal_called = false;
}

// Test hook implementation - called by real handle_validated_message
void test_hook_handle_validated_message_called(message_type_t msg_type, uint8_t* payload, uint16_t len) {
    mock_handle_validated_message_called = true;
    last_msg_type = msg_type;
    if (payload && len > 0 && len <= MAX_PAYLOAD_SIZE) {
        memcpy(last_payload, payload, len);
    }
    last_len = len;
}

// Helper to preload the read buffer for receive tests
void load_mock_buffer(const uint8_t* data, uint16_t len) {
    // Inject data directly into serial.c's rx_buffer
    test_inject_rx_data(data, len);
}

// Helpers to get results from the write buffer
const uint8_t* get_mock_buffer(void) { return mock_serial_buffer; }
uint16_t get_mock_buffer_len(void) { return write_idx - read_idx; }

// Spy "getter" functions to check results
bool was_handler_called(void) { return mock_handle_validated_message_called; }
message_type_t get_last_msg_type(void) { return last_msg_type; }
uint16_t get_last_len(void) { return last_len; }
void get_last_payload(uint8_t* buffer) { memcpy(buffer, last_payload, last_len); }
bool was_shutdown_signal_called(void) { return mock_send_shutdown_signal_called; } // <-- Getter for the new spy


// ========================================================================
// ## Mock Implementations of Hardware/External Functions
// ========================================================================

// Mock implementation of send_shutdown_signal
void send_shutdown_signal(void) {
    mock_send_shutdown_signal_called = true;
    // In the mock, we don't actually send a message, we just record the call.
}

void tud_cdc_write_char(char c) {
    if (write_idx < sizeof(mock_serial_buffer)) {
        mock_serial_buffer[write_idx++] = c;
    }
}

int getchar_timeout_us(uint32_t timeout_us) {
    if (read_idx < write_idx) {
        return mock_serial_buffer[read_idx++];
    }
    return PICO_ERROR_TIMEOUT;
}

uint32_t tud_cdc_write_available(void) {
    return sizeof(mock_serial_buffer) - write_idx;
}

void tud_cdc_write_flush(void) {
    // Does nothing in mock.
}

// FreeRTOS mock implementations
BaseType_t xTaskCreate(TaskFunction_t pvTaskCode, const char *const pcName,
                       uint16_t usStackDepth, void *pvParameters,
                       uint32_t uxPriority, TaskHandle_t *pxCreatedTask) {
    (void)pvTaskCode;
    (void)pcName;
    (void)usStackDepth;
    (void)pvParameters;
    (void)uxPriority;
    (void)pxCreatedTask;
    // In unit tests, tasks don't actually run
    return 1; // pdPASS
}

void vTaskDelay(TickType_t xTicksToDelay) {
    (void)xTicksToDelay;
    // In unit tests, delays are no-ops
}

void vTaskDelete(TaskHandle_t xTaskToDelete) {
    (void)xTaskToDelete;
    // In unit tests, task deletion is a no-op
}

// Mock debug print function
void print_dbg(const char *format, ...) {
    // In unit tests, suppress debug output
    (void)format;
}

// Mock random number generation
// Uses Xorshift32 for better distribution across all bits
uint32_t get_rand_32(void) {
    static uint32_t state = 0x12345678;

    // Xorshift32 algorithm - good period and distribution
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;

    return state;
}

// Mock delay function
void pico_delay_ms(uint32_t ms) {
    (void)ms;
    // In tests, do nothing (time is controlled by mock_time)
}

// Note: send_message is provided by real serial.c
// Note: handle_validated_message is provided by real protocol.c