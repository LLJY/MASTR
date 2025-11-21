#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>

// program specific headers
#include "constants.h"
#include "serial.h"
#include "protocol.h"
#include "crypto.h"

// pico library headers
// DO NOT INCLUDE THESE DURING UNIT TESTING.
#ifndef UNIT_TEST
#include "pico/binary_info.h"
#endif

#ifdef UNIT_TEST
    #include "mock_pico_sdk.h" // Use our mock declarations for the test build
#else
    #include "pico/stdlib.h"   // Use the real SDK for the hardware build
    #include "hardware/irq.h"  // For irq_set_priority
    #include "tusb.h"
    #include "FreeRTOS.h"
    #include "semphr.h"
#endif

// Ring buffer for interrupt-driven reception
#define RX_BUFFER_SIZE 512
static uint8_t g_rx_buffer[RX_BUFFER_SIZE];
static volatile uint16_t g_rx_write_idx = 0;
static volatile uint16_t g_rx_read_idx = 0;

#ifndef UNIT_TEST
// Task handle for direct task notification (more efficient than semaphore)
static TaskHandle_t serial_task_handle = NULL;
#endif

// Frame processing state
static uint8_t g_frame_buffer[MAX_PAYLOAD_SIZE + 4]; // 4 is the size of the frame metadata
static uint16_t g_frame_len = 0;
static bool g_in_frame = false;
static bool g_in_escape = false;

// Forward declarations
void print_dbg(const char *format, ...);

#ifndef UNIT_TEST
// USB CDC RX callback - called from interrupt context
__attribute__((hot, flatten))
void tud_cdc_rx_cb(uint8_t itf) {
    (void)itf;
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    
    // Directly notify the serial task (faster and more efficient than semaphore)
    // 
    // don't even send or recieve anything if protocol state is unprovisioned (0x10) or halt (0xFF)
    if (likely(serial_task_handle != NULL &&
               g_protocol_state.current_state != PROTOCOL_STATE_UNPROVISIONED &&
               g_protocol_state.current_state != 0xFF)) {
        vTaskNotifyGiveFromISR(serial_task_handle, &xHigherPriorityTaskWoken);
        portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
    }
}

void serial_init(TaskHandle_t task_handle) {
    // Store the task handle for direct notifications
    serial_task_handle = task_handle;
    
    if (serial_task_handle == NULL) {
        return;
    }
    
    // set proper irq priority for FreeRTOS (i like to be specific, since we have to set it for RP2350)
    // Must be >= configMAX_SYSCALL_INTERRUPT_PRIORITY to call vTaskNotifyGiveFromISR
    //   RP2040: 0x40 + 0x20 = 0x60 (safe, middle priority)
    //   RP2350: 0x50 + 0x20 = 0x70 (safe, middle priority)
    // Lower number = higher priority, so we ADD to make it LOWER priority
    irq_set_priority(USBCTRL_IRQ, configMAX_SYSCALL_INTERRUPT_PRIORITY + 0x20);
}
#else
void serial_init(TaskHandle_t task_handle) {
    // Mock implementation for unit tests
    (void)task_handle;
}
#endif

// Read data from USB CDC into ring buffer
static inline uint16_t rx_buffer_available() {
    return (g_rx_write_idx >= g_rx_read_idx) ?
           (g_rx_write_idx - g_rx_read_idx) :
           (RX_BUFFER_SIZE - g_rx_read_idx + g_rx_write_idx);
}

static inline bool rx_buffer_get(uint8_t *byte) {
    if (g_rx_read_idx == g_rx_write_idx) {
        return false; // Buffer empty
    }
    *byte = g_rx_buffer[g_rx_read_idx];
    g_rx_read_idx = (g_rx_read_idx + 1) % RX_BUFFER_SIZE;
    return true;
}

static void rx_buffer_fill() {
    #ifndef UNIT_TEST
    while (tud_cdc_available()) {
        uint16_t next_write = (g_rx_write_idx + 1) % RX_BUFFER_SIZE;
        if (next_write == g_rx_read_idx) {
            // Buffer full, drop data
            print_dbg("RX buffer overflow!");
            break;
        }
        
        int c = tud_cdc_read_char();
        if (c >= 0) {
            g_rx_buffer[g_rx_write_idx] = (uint8_t)c;
            g_rx_write_idx = next_write;
        }
    }
    #endif
}

#ifdef UNIT_TEST
// Test helper to inject data into rx_buffer for unit tests
void test_inject_rx_data(const uint8_t* data, uint16_t len) {
    for (uint16_t i = 0; i < len; i++) {
        uint16_t next_write = (g_rx_write_idx + 1) % RX_BUFFER_SIZE;
        if (next_write != g_rx_read_idx) {
            g_rx_buffer[g_rx_write_idx] = data[i];
            g_rx_write_idx = next_write;
        }
    }
}
#endif

void serial_process_data(void)
{
    #ifndef UNIT_TEST
    // Wait for notification from ISR (pure event-driven, no polling)
    // This is more efficient than semaphores and has counting behavior
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    
    // Fill buffer from USB CDC
    rx_buffer_fill();
    #endif
    
    // Process all available bytes in the ring buffer
    uint8_t c;
    while (rx_buffer_get(&c)) {
        // escape sequence handling with byte stuffing
        if (g_in_escape) {
            g_in_escape = false;
            uint8_t unstuffed_byte;
            switch (c) {
                case ESC_SUB_SOF: unstuffed_byte = SOF_BYTE; break;
                case ESC_SUB_EOF: unstuffed_byte = EOF_BYTE; break;
                case ESC_SUB_ESC: unstuffed_byte = ESC_BYTE; break;
                default:
                    // PROTOCOL ERROR: Invalid byte after ESC. Abort frame.
                    g_in_frame = false;
                    print_dbg("PROTOCOL ERROR: Invalid escape sequence: 0x%02X", c);
                    continue;
            }
            
            // no need to sizeof if you already have the magic numbers to do so.
            if (g_in_frame && g_frame_len < (MAX_PAYLOAD_SIZE + 4)) {
                g_frame_buffer[g_frame_len++] = unstuffed_byte;
            }
            continue;
        }

        switch (c) {
            case SOF_BYTE:
                // reset when SOF
                g_in_frame = true;
                g_in_escape = false;
                g_frame_len = 0;
                break;

            case EOF_BYTE:
                // EOF reached, complete the processing.
                if (g_in_frame) {
                    g_in_frame = false;
                    serial_process_complete_frame();
                }
                break;

            case ESC_BYTE:
                // this is the start of a sequence
                g_in_escape = true;
                break;

            default:
                // Normal data byte
                if (g_in_frame && g_frame_len < sizeof(g_frame_buffer)) {
                    g_frame_buffer[g_frame_len++] = c;
                }
                break;
        }
    }
}

static void serial_process_complete_frame() {
    // Decrypt frame if protocol state requires it
    uint8_t decrypted_frame[MAX_PAYLOAD_SIZE + 4] = {0};
    uint16_t decrypted_len = 0;
    
    if (!crypto_decrypt_frame_if_needed(g_frame_buffer, g_frame_len, decrypted_frame, &decrypted_len)) {
        print_dbg("CRYPTO ERROR: Failed to decrypt frame\n");
        send_shutdown_signal();
        return;
    }
    
    // Frame must have at least 4 bytes: Type(1), Length(2), Checksum(1)
    if (decrypted_len < 4) {
        print_dbg("FRAME ERROR: Frame too short (%d bytes)\n", decrypted_len);
        send_shutdown_signal();
        return;
    }
    
    // Extract message type
    message_type_t received_msg_type = decrypted_frame[0];
    
    /**
     * Explaining the byte receiving magic.
     *
     * In order to combine two bytes into a 16bit number you have to do some magic.
     *
     * Assuming 2 numbers to represent high (MSB) 10101010 and low (LSB) 01010101
     *
     * EXTRACTING THE UPPER 8 BITS:
     * Cast the first byte to uint16_t and shift left 8 bits
     * 0000000010101010 << 8 = 1010101000000000
     *
     * EXTRACTING THE LOWER 8 BITS:
     * Cast the second byte to uint16_t (no shift needed)
     * 0000000001010101
     *
     * COMBINING:
     * OR them together: 1010101000000000 | 0000000001010101 = 1010101001010101
     */
    uint16_t payload_len = ((uint16_t)decrypted_frame[1] << 8) | decrypted_frame[2];
    
    // Extract checksum (last byte)
    uint8_t received_checksum = decrypted_frame[decrypted_len - 1];
    
    // verify packet length consistency
    // The actual payload length is the total frame length minus the header and checksum bytes
    uint16_t actual_payload_len = decrypted_len - 4;
    if (payload_len != actual_payload_len) {
        print_dbg("FRAME ERROR: Length mismatch. Header says %d, actual is %d\n",
                  payload_len, actual_payload_len);
        send_shutdown_signal();
        return;
    }
    
    // verify the checksum, this is just a rolling unsigned 8 bit number.
    // since unsigned overflows are defined behaviour in C standards. We can safely do this.
    // most importantly it must produce a consistent result, which it does.
    uint8_t calculated_checksum = 0;
    for (uint16_t i = 0; i < decrypted_len - 1; i++) {
        calculated_checksum += decrypted_frame[i];
    }
    
    if (calculated_checksum != received_checksum) {
        print_dbg("CHECKSUM ERROR: Expected %d, got %d\n",
                  calculated_checksum, received_checksum);
        send_shutdown_signal();
        return;
    }

    print_dbg("Frame validated: type=0x%02X, payload_len=%d\n", received_msg_type, payload_len);
    
    // Extract payload
    uint8_t *payload = &decrypted_frame[3];
    
    // Pass the payload to the handler
    protocol_handle_validated_message(received_msg_type, payload, payload_len);
}

static inline void send_stuffed_byte(const uint8_t c) {
    switch(c){
        case SOF_BYTE:
            tud_cdc_write_char(ESC_BYTE);
            tud_cdc_write_char(ESC_SUB_SOF);
            break;
        case EOF_BYTE:
            tud_cdc_write_char(ESC_BYTE);
            tud_cdc_write_char(ESC_SUB_EOF);
            break;
        case ESC_BYTE:
            tud_cdc_write_char(ESC_BYTE);
            tud_cdc_write_char(ESC_SUB_ESC);
            break;
        default:
            tud_cdc_write_char(c);
    }
}


// REVISED send_message function
void send_message(uint8_t msg_type, uint8_t *payload, uint16_t len)
{
    // Build frame: Type(1) + Length(2) + Payload(N) + Checksum(1)
    uint8_t frame_buffer[MAX_PAYLOAD_SIZE + 4];
    uint16_t frame_len = 0;
    
    // Type
    frame_buffer[frame_len++] = msg_type;
    
    /**
     * Explaining the byte sending magic.
     *
     * In order to split a 16bit number into two bytes over serial 2*8 bit you have to do some magic to split
     * then combine them later.
     *
     * assuming 2 numbers to represent high (MSB) 10101010 and low (LSB) 01010101
     * 1010101001010101
     *
     * EXTRACTING THE UPPER 8 BITS:
     * bitshift right 8 bits to carve out the MSB.
     * 0000000010101010
     *
     * AND with 11111111 mask, to ensure you ONLY get the lower 8 bits.
     * Cast to 8 bit -> 10101010
     *
     * EXTRACTING THE LOWER 8 BITS:
     * this is much simpler, no need to bitshift. Just do & 0xFF and cast.
     *
     */
    frame_buffer[frame_len++] = (len >> 8) & 0xFF;  // Length MSB
    frame_buffer[frame_len++] = len & 0xFF;          // Length LSB
    
    // Payload
    for (uint16_t i = 0; i < len; i++) {
        frame_buffer[frame_len++] = payload[i];
    }
    
    // Checksum
    uint8_t checksum = 0;
    for (uint16_t i = 0; i < frame_len; i++) {
        checksum += frame_buffer[i];
    }
    frame_buffer[frame_len++] = checksum;
    
    // Encrypt frame if protocol state requires it
    uint8_t encrypted_frame[MAX_PAYLOAD_SIZE + 4 + ENCRYPTION_OVERHEAD];
    uint16_t encrypted_len = 0;
    
    if (!crypto_encrypt_frame_if_needed(msg_type, frame_buffer, frame_len, encrypted_frame, &encrypted_len)) {
        print_dbg("CRYPTO ERROR: Failed to encrypt outgoing frame\n");
        return;
    }
    
    // Send the frame (encrypted or plaintext)
    uint8_t* frame_to_send = encrypted_frame;
    uint16_t len_to_send = encrypted_len;

    // The required buffer space is harder to predict due to stuffing.
    // A safe estimate is double the packet size, plus frame bytes.
    uint32_t required_space = (2 + len_to_send) * 2;
    if (tud_cdc_write_available() < required_space)
    {
        tud_cdc_write_flush();
    }

    // Send Start of Frame (un-stuffed)
    tud_cdc_write_char(SOF_BYTE);

    // Send frame data (stuffed)
    for (uint16_t i = 0; i < len_to_send; i++)
    {
        send_stuffed_byte(frame_to_send[i]);
    }

    // Send End of Frame (un-stuffed)
    tud_cdc_write_char(EOF_BYTE);

    // CRITICAL: Flush the buffer to send the packet now.
    tud_cdc_write_flush();
}

#ifndef UNIT_TEST
// Debug print function that sends via DEBUG_MSG protocol
// Safe to call even when DEBUG is not defined - will do nothing in that case
void print_dbg(const char *format, ...) {
    #ifdef DEBUG
    char buffer[128];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    send_message(DEBUG_MSG, (uint8_t*)buffer, strlen(buffer));
    #else
    (void)format;  // Suppress unused parameter warning
    #endif
}

void send_shutdown_signal(void)
{
    print_dbg("SHUTDOWN: Integrity failure detected");
    send_message(T2H_INTEGRITY_FAIL_HALT, NULL, 0);
}
#endif