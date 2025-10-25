#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>

// program specific headers
#include "constants.h"
#include "serial.h"
#include "protocol.h"
#include "crypt.h"

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
static uint8_t rx_buffer[RX_BUFFER_SIZE];
static volatile uint16_t rx_write_idx = 0;
static volatile uint16_t rx_read_idx = 0;

#ifndef UNIT_TEST
// Task handle for direct task notification (more efficient than semaphore)
static TaskHandle_t serial_task_handle = NULL;
#endif

// Frame processing state
static uint8_t frame_buffer[MAX_PAYLOAD_SIZE + 4]; // 4 is the size of the frame metadata
static uint16_t frame_len = 0;
static bool in_frame = false;
static bool in_escape = false;

// Forward declarations
void print_dbg(const char *format, ...);

#ifndef UNIT_TEST
// USB CDC RX callback - called from interrupt context
void tud_cdc_rx_cb(uint8_t itf) {
    (void)itf;
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    
    // Directly notify the serial task (faster and more efficient than semaphore)
    if (serial_task_handle != NULL) {
        vTaskNotifyGiveFromISR(serial_task_handle, &xHigherPriorityTaskWoken);
        portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
    }
}

void serial_init(TaskHandle_t task_handle) {
    // Store the task handle for direct notifications
    serial_task_handle = task_handle;
    
    if (serial_task_handle == NULL) {
        print_dbg("WARNING: serial_init called with NULL task handle\n");
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
    return (rx_write_idx >= rx_read_idx) ? 
           (rx_write_idx - rx_read_idx) : 
           (RX_BUFFER_SIZE - rx_read_idx + rx_write_idx);
}

static inline bool rx_buffer_get(uint8_t *byte) {
    if (rx_read_idx == rx_write_idx) {
        return false; // Buffer empty
    }
    *byte = rx_buffer[rx_read_idx];
    rx_read_idx = (rx_read_idx + 1) % RX_BUFFER_SIZE;
    return true;
}

static void rx_buffer_fill() {
    #ifndef UNIT_TEST
    while (tud_cdc_available()) {
        uint16_t next_write = (rx_write_idx + 1) % RX_BUFFER_SIZE;
        if (next_write == rx_read_idx) {
            // Buffer full, drop data
            print_dbg("RX buffer overflow!");
            break;
        }
        
        int c = tud_cdc_read_char();
        if (c >= 0) {
            rx_buffer[rx_write_idx] = (uint8_t)c;
            rx_write_idx = next_write;
        }
    }
    #endif
}

void process_serial_data()
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
        if (in_escape) {
            in_escape = false;
            uint8_t unstuffed_byte;
            switch (c) {
                case ESC_SUB_SOF: unstuffed_byte = SOF_BYTE; break;
                case ESC_SUB_EOF: unstuffed_byte = EOF_BYTE; break;
                case ESC_SUB_ESC: unstuffed_byte = ESC_BYTE; break;
                default:
                    // PROTOCOL ERROR: Invalid byte after ESC. Abort frame.
                    in_frame = false;
                    print_dbg("PROTOCOL ERROR: Invalid escape sequence: 0x%02X", c);
                    continue;
            }
            
            // no need to sizeof if you already have the magic numbers to do so.
            if (in_frame && frame_len < (MAX_PAYLOAD_SIZE + 4)) {
                frame_buffer[frame_len++] = unstuffed_byte;
            }
            continue;
        }

        switch (c) {
            case SOF_BYTE:
                // reset when SOF
                in_frame = true;
                in_escape = false;
                frame_len = 0;
                break;

            case EOF_BYTE:
                // EOF reached, complete the processing.
                if (in_frame) {
                    in_frame = false;
                    process_complete_frame();
                }
                break;

            case ESC_BYTE:
                // this is the start of a sequence
                in_escape = true;
                break;

            default:
                // Normal data byte
                if (in_frame && frame_len < sizeof(frame_buffer)) {
                    frame_buffer[frame_len++] = c;
                }
                break;
        }
    }
}

static void process_complete_frame() {
    // Frame must have at least 4 bytes: Type(1), Length(2), Checksum(1)
    if (frame_len < 4) {
        print_dbg("FRAME ERROR: Frame too short (%d bytes)", frame_len);
        return; // Invalid frame
    }

    // Decrypt frame if protocol state requires it
    // The decrypt_frame_if_needed function checks the protocol state and
    // either decrypts the payload or passes it through unchanged
    uint8_t decrypted_payload[MAX_PAYLOAD_SIZE];
    uint16_t decrypted_len = 0;
    
    if (!decrypt_frame_if_needed(frame_buffer, frame_len, decrypted_payload, &decrypted_len)) {
        print_dbg("CRYPTO ERROR: Failed to process frame encryption\n");
        send_shutdown_signal();
        return;
    }
    
    // Extract message type and validate frame structure
    message_type_t received_msg_type = frame_buffer[0];
    
    // Get the original encrypted length from the frame for checksum validation
    uint16_t frame_payload_len = ((uint16_t)frame_buffer[1] << 8) | frame_buffer[2];

    // get the checksum, which is the last bit.
    uint8_t received_checksum = frame_buffer[frame_len - 1];
    
    // verify packet length consistency
    // The actual payload length is the total frame length minus the header and checksum bytes
    if (frame_payload_len != (frame_len - 4)) {
        print_dbg("FRAME ERROR: Length mismatch. Header says %d, actual is %d", 
                  frame_payload_len, frame_len - 4);
        send_shutdown_signal(); // Protocol error
        return;
    }
    
    // verify the checksum, this is just a rolling unsigned 8 bit number.
    // since unsigned overflows are defined behaviour in C standards. We can safely do this.
    // most importantly it must produce a consistent result, which it does.
    uint8_t calculated_checksum = 0;
    for (uint16_t i = 0; i < frame_len - 1; i++) { // Checksum over everything EXCEPT the checksum byte itself
        calculated_checksum += frame_buffer[i];
    }
    
    if (calculated_checksum != received_checksum) {
        print_dbg("CHECKSUM ERROR: Expected %d, got %d", 
                  calculated_checksum, received_checksum);
        send_shutdown_signal(); // Integrity error
        return;
    }

    // DEBUG: Frame validated successfully
    print_dbg("Frame validated: type=0x%02X, payload_len=%d\n", received_msg_type, decrypted_len);
    
    // Pass the DECRYPTED payload to the handler
    handle_validated_message(received_msg_type, decrypted_payload, decrypted_len);
}

static void send_stuffed_byte(uint8_t c) {
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
    // Encrypt the payload if protocol state requires it
    uint8_t encrypted_payload[MAX_PAYLOAD_SIZE + ENCRYPTION_OVERHEAD];
    uint16_t encrypted_len = 0;
    
    if (!encrypt_frame_if_needed(msg_type, payload, len, encrypted_payload, &encrypted_len)) {
        print_dbg("CRYPTO ERROR: Failed to encrypt outgoing frame\n");
        return;
    }
    
    // Now send the encrypted payload (or passthrough if not encrypted)
    uint8_t* payload_to_send = encrypted_payload;
    uint16_t len_to_send = encrypted_len;

    // The required buffer space is harder to predict due to stuffing.
    // A safe estimate is double the packet size, plus frame bytes.
    uint32_t required_space = (5 + len_to_send) * 2;
    if (tud_cdc_write_available() < required_space)
    {
        tud_cdc_write_flush();
    }

    uint8_t checksum = 0;

    // 1. Send Start of Frame (un-stuffed)
    tud_cdc_write_char(SOF_BYTE);

    // 2. Send Message Type (stuffed)
    send_stuffed_byte(msg_type);
    checksum += msg_type;

    // 3. Send Length (stuffed)

    /**
     * Explaining the byte sending magic.
     * 
     * In order to split a 16bit number into two bytes over serial 2*8 bit you have to do some magic to split
     * then combine them later.
     * 
     * assuming 2 numbers to represent high (MSB) 10101010 and low (LSB) 010101
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
    uint8_t len_high = (len_to_send >> 8) & 0xFF;
    uint8_t len_low = len_to_send & 0xFF;
    send_stuffed_byte(len_high);
    send_stuffed_byte(len_low);
    checksum += len_high;
    checksum += len_low;

    // 4. Send the Payload (stuffed) - now using encrypted payload
    for (uint16_t i = 0; i < len_to_send; i++)
    {
        send_stuffed_byte(payload_to_send[i]);
        checksum += payload_to_send[i];
    }

    // 5. Send the final Checksum (stuffed)
    send_stuffed_byte(checksum);

    // 6. Send End of Frame (un-stuffed)
    tud_cdc_write_char(EOF_BYTE);

    // 7. CRITICAL: Flush the buffer to send the packet now.
    tud_cdc_write_flush();
}

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

#ifndef UNIT_TEST
void send_shutdown_signal()
{
    print_dbg("SHUTDOWN: Integrity failure detected");
    send_message(T2H_INTEGRITY_FAIL_HALT, NULL, 0);
}
#endif