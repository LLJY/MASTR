#include <stdint.h>
#include <string.h>
#include <stdbool.h>

// program specific headers
#include "constants.h"
#include "serial.h"
#include "protocol.h"

// pico library headers
// DO NOT INCLUDE THESE DURING UNIT TESTING.
#ifndef UNIT_TEST
#include "pico/binary_info.h"
#endif

#ifdef UNIT_TEST
    #include "mock_pico_sdk.h" // Use our mock declarations for the test build
    #include <stdio.h>
#else
    #include "pico/stdlib.h"   // Use the real SDK for the hardware build
    #include "tusb.h"
#endif

// new frame
static uint8_t frame_buffer[MAX_PAYLOAD_SIZE + 4]; // 4 is the size of the frame metadata
static uint16_t frame_len = 0;
static bool in_frame = false;
static bool in_escape = false;

void process_serial_data()
{
    int c_int = getchar_timeout_us(0);
    if (c_int == PICO_ERROR_TIMEOUT) return;
    uint8_t c = (uint8_t)c_int;

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
                #ifdef DEBUG
                printf("PROTOCOL ERROR: Invalid escape sequence: 0x%02X\n", c);
                #endif
                return;
        }
        
        // no need to sizeof if you already have the magic numbers to do so.
        if (in_frame && frame_len < (MAX_PAYLOAD_SIZE + 4)) {
            frame_buffer[frame_len++] = unstuffed_byte;
        }
        return;
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

static void process_complete_frame() {
    // Frame must have at least 4 bytes: Type(1), Length(2), Checksum(1)
    if (frame_len < 4) {
        #ifdef DEBUG
        printf("FRAME ERROR: Frame too short (%d bytes)\n", frame_len);
        #endif
        return; // Invalid frame
    }

    // get the message type and payload length from the buffer
    message_type_t received_msg_type = frame_buffer[0];

    // 
    // 
    /* we have to do some byte manipulation magic to squeeze two 8 bits into one 16 bit
     * more magic when sending !!
     *
     * Note: the protocol sends bytes in big endian ordering.
     * 
     * What actually is happening here is the 8 bit is being casted into a 16 bit
     * e.g. 10101010 -> 0000000010101010
     * 
     * we bit shift it left 8 bits -> 1010101000000000
     * Then add the LSB bits, which are contained in the next half
     * we can do this using the bitwise OR function (ORR in ARM instructions).
     * 
     * (boolean algebra notation)
     * 1010101000000000 | 01010101 = 1010101001010101
     * 
     * <this part wasn't chatgpt'ed i spent good time doing this.>
     */
    uint16_t received_payload_len = ((uint16_t)frame_buffer[1] << 8) | frame_buffer[2];

    // get the checksum, which is the last bit.
    uint8_t received_checksum = frame_buffer[frame_len - 1];
    
    // verify packet length consistency
    // The actual payload length is the total frame length minus the header and checksum bytes
    if (received_payload_len != (frame_len - 4)) {
        #ifdef DEBUG
        printf("FRAME ERROR: Length mismatch. Header says %d, actual is %d\n", received_payload_len, frame_len - 4);
        #endif
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
        #ifdef DEBUG
        printf("CHECKSUM ERROR: Expected %d, got %d\n", calculated_checksum, received_checksum);
        #endif
        send_shutdown_signal(); // Integrity error
        return;
    }

    handle_validated_message(received_msg_type, &frame_buffer[3], received_payload_len);
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
    // The required buffer space is harder to predict due to stuffing.
    // A safe estimate is double the packet size, plus frame bytes.
    uint32_t required_space = (5 + len) * 2;
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
     * Explaning the byte sending magic.
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
     * Since & 0xFF will already extract the lower 8 bits. you get:
     * 1010101001010101 & 11111111 = 01010101
     * 
     */
    uint8_t len_high = (len >> 8) & 0xFF;
    uint8_t len_low = len & 0xFF;
    send_stuffed_byte(len_high);
    send_stuffed_byte(len_low);
    checksum += len_high;
    checksum += len_low;

    // 4. Send the Payload (stuffed)
    for (uint16_t i = 0; i < len; i++)
    {
        send_stuffed_byte(payload[i]);
        checksum += payload[i];
    }

    // 5. Send the final Checksum (stuffed)
    send_stuffed_byte(checksum);

    // 6. Send End of Frame (un-stuffed)
    tud_cdc_write_char(EOF_BYTE);

    // 7. CRITICAL: Flush the buffer to send the packet now.
    tud_cdc_write_flush();
}

#ifndef UNIT_TEST
void send_shutdown_signal()
{
    #ifdef DEBUG
    uint8_t *payload = (uint8_t *)"DEBUG SHUTDOWN MESSAGE";
    send_message(DEBUG_MSG, payload, strlen((char*)payload));
    #endif

    send_message(T2H_INTEGRITY_FAIL_HALT, NULL, 0);
}
#endif