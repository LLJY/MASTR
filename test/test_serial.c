#include "unity.h"
#include "mock_pico_sdk.h"  // Must be before serial.h to define TaskHandle_t
#include "constants.h"
#include "protocol.h"
#include "serial.h"
#include <stdbool.h>
#include <string.h>

// --- External declarations for our mocks and helpers ---
void reset_mocks(void);
void load_mock_buffer(const uint8_t* data, uint16_t len);
const uint8_t* get_mock_buffer(void);
uint16_t get_mock_buffer_len(void);

// Spy getters
bool was_handler_called(void);
message_type_t get_last_msg_type(void);
uint16_t get_last_len(void);
void get_last_payload(uint8_t* buffer);
bool was_shutdown_signal_called(void);


// setUp and tearDown are in test_common.c

// ========================================================================
// ## Test Suite 1: send_message() (Stuffing and Framing)
// ========================================================================

void test_send_simple_packet(void) {
    // Arrange: Create 3-byte payload and expected framed output
    uint8_t payload[] = {0x01, 0x02, 0x03};
    uint8_t expected_checksum = T2H_BOOT_OK + 0x00 + 0x03 + 0x01 + 0x02 + 0x03;
    uint8_t expected_frame[] = {
        SOF_BYTE,
        T2H_BOOT_OK,
        0x00, 0x03,
        0x01, 0x02, 0x03,
        expected_checksum,
        EOF_BYTE
    };

    // Act: Send message through serial framing layer
    send_message(T2H_BOOT_OK, payload, sizeof(payload));

    // Assert: Verify correct SOF/EOF framing and checksum
    TEST_ASSERT_EQUAL_UINT16(sizeof(expected_frame), get_mock_buffer_len());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_frame, get_mock_buffer(), sizeof(expected_frame));
}

void test_send_with_all_special_bytes_in_payload(void) {
    // Arrange: Payload containing SOF, EOF, ESC bytes that require stuffing
    uint8_t payload[] = {SOF_BYTE, EOF_BYTE, ESC_BYTE};
    uint8_t expected_checksum = H2T_HEARTBEAT + 0x00 + 0x03 + SOF_BYTE + EOF_BYTE + ESC_BYTE;
    uint8_t expected_stuffed_frame[] = {
        SOF_BYTE,
        H2T_HEARTBEAT,
        0x00, 0x03,
        ESC_BYTE, ESC_SUB_SOF,
        ESC_BYTE, ESC_SUB_EOF,
        ESC_BYTE, ESC_SUB_ESC,
        expected_checksum,
        EOF_BYTE
    };

    // Act: Send message with special bytes
    send_message(H2T_HEARTBEAT, payload, sizeof(payload));

    // Assert: Verify all special bytes are properly escaped
    TEST_ASSERT_EQUAL_UINT16(sizeof(expected_stuffed_frame), get_mock_buffer_len());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_stuffed_frame, get_mock_buffer(), sizeof(expected_stuffed_frame));
}

void test_send_zero_length_payload(void) {
    // Arrange: Expected frame with zero payload length
    uint8_t expected_checksum = T2H_INTEGRITY_FAIL_HALT + 0x00 + 0x00;
    uint8_t expected_frame[] = {
        SOF_BYTE,
        T2H_INTEGRITY_FAIL_HALT,
        0x00, 0x00,
        expected_checksum,
        EOF_BYTE
    };

    // Act: Send message with NULL payload
    send_message(T2H_INTEGRITY_FAIL_HALT, NULL, 0);

    // Assert: Verify frame is created correctly without payload bytes
    TEST_ASSERT_EQUAL_UINT16(sizeof(expected_frame), get_mock_buffer_len());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_frame, get_mock_buffer(), sizeof(expected_frame));
}


// ========================================================================
// ## Test Suite 2: serial_process_data() (Unstuffing and Validation)
// ========================================================================

void test_receive_simple_packet(void) {
    // Arrange: Valid framed packet in receive buffer
    uint8_t original_payload[] = {0xAA, 0xBB, 0xCC};
    uint8_t checksum = H2T_ECDH_SHARE + 0x00 + 0x03 + 0xAA + 0xBB + 0xCC;
    uint8_t frame_on_wire[] = { SOF_BYTE, H2T_ECDH_SHARE, 0x00, 0x03, 0xAA, 0xBB, 0xCC, checksum, EOF_BYTE };
    uint8_t received_payload[3] = {0};

    // Act: Process received serial data
    load_mock_buffer(frame_on_wire, sizeof(frame_on_wire));
    serial_process_data();
    get_last_payload(received_payload);

    // Assert: Verify handler called with correct message type and payload
    TEST_ASSERT_TRUE(was_handler_called());
    TEST_ASSERT_EQUAL(H2T_ECDH_SHARE, get_last_msg_type());
    TEST_ASSERT_EQUAL_UINT16(sizeof(original_payload), get_last_len());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(original_payload, received_payload, sizeof(original_payload));
}

void test_receive_stuffed_packet(void) {
    // Arrange: Framed packet with escaped special bytes
    uint8_t original_payload[] = {SOF_BYTE, 0x11, EOF_BYTE, 0x22, ESC_BYTE};
    uint8_t checksum = H2T_INTEGRITY_RESPONSE + 0x00 + 0x05 + SOF_BYTE + 0x11 + EOF_BYTE + 0x22 + ESC_BYTE;
    uint8_t frame_on_wire[] = {
        SOF_BYTE,
        H2T_INTEGRITY_RESPONSE, 0x00, 0x05,
        ESC_BYTE, ESC_SUB_SOF,
        0x11,
        ESC_BYTE, ESC_SUB_EOF,
        0x22,
        ESC_BYTE, ESC_SUB_ESC,
        checksum,
        EOF_BYTE
    };
    uint8_t received_payload[5] = {0};
    
    // Act: Process stuffed frame
    load_mock_buffer(frame_on_wire, sizeof(frame_on_wire));
    serial_process_data();
    get_last_payload(received_payload);

    // Assert: Verify unstuffing restored original payload
    TEST_ASSERT_TRUE(was_handler_called());
    TEST_ASSERT_EQUAL_UINT16(sizeof(original_payload), get_last_len());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(original_payload, received_payload, sizeof(original_payload));
}

void test_receive_zero_length_packet(void) {
    // Arrange: Frame with zero-length payload
    uint8_t checksum = T2H_HEARTBEAT_ACK + 0x00 + 0x00;
    uint8_t frame_on_wire[] = { SOF_BYTE, T2H_HEARTBEAT_ACK, 0x00, 0x00, checksum, EOF_BYTE };

    // Act: Process empty payload message
    load_mock_buffer(frame_on_wire, sizeof(frame_on_wire));
    serial_process_data();

    // Assert: Verify handler called with zero length
    TEST_ASSERT_TRUE(was_handler_called());
    TEST_ASSERT_EQUAL(T2H_HEARTBEAT_ACK, get_last_msg_type());
    TEST_ASSERT_EQUAL_UINT16(0, get_last_len());
}

void test_ignore_bytes_before_SOF(void) {
    // Arrange: Garbage bytes followed by valid frame
    uint8_t original_payload[] = {0x01};
    uint8_t checksum = H2T_HEARTBEAT + 0x00 + 0x01 + 0x01;
    uint8_t frame_on_wire[] = { 0xDE, 0xAD, 0xBE, 0xEF, SOF_BYTE, H2T_HEARTBEAT, 0x00, 0x01, 0x01, checksum, EOF_BYTE };
    uint8_t received_payload[1] = {0};

    // Act: Process stream with leading garbage
    load_mock_buffer(frame_on_wire, sizeof(frame_on_wire));
    serial_process_data();
    get_last_payload(received_payload);
    
    // Assert: Verify parser skipped garbage and found valid frame
    TEST_ASSERT_TRUE(was_handler_called());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(original_payload, received_payload, sizeof(original_payload));
}

// ========================================================================
// ## Test Suite 3: Error Handling and Robustness
// ========================================================================

void test_reject_bad_checksum(void) {
    // Arrange: Frame with intentionally corrupted checksum
    uint8_t checksum = H2T_CHANNEL_VERIFY_RESPONSE + 0x00 + 0x01 + 0xAB;
    uint8_t frame_on_wire[] = { SOF_BYTE, H2T_CHANNEL_VERIFY_RESPONSE, 0x00, 0x01, 0xAB, checksum + 1, EOF_BYTE };

    // Act: Process frame with bad checksum
    load_mock_buffer(frame_on_wire, sizeof(frame_on_wire));
    serial_process_data();
    
    // Assert: Verify handler not called and shutdown triggered
    TEST_ASSERT_FALSE(was_handler_called());
    TEST_ASSERT_TRUE(was_shutdown_signal_called());
}

void test_reject_bad_length(void) {
    // Arrange: Header declares length=5 but only 2 bytes provided
    uint8_t checksum = H2T_INTEGRITY_RESPONSE + 0x00 + 0x05 + 0xAA + 0xBB;
    uint8_t frame_on_wire[] = { SOF_BYTE, H2T_INTEGRITY_RESPONSE, 0x00, 0x05, 0xAA, 0xBB, checksum, EOF_BYTE };

    // Act: Process frame with length mismatch
    load_mock_buffer(frame_on_wire, sizeof(frame_on_wire));
    serial_process_data();
    
    // Assert: Verify frame rejected and shutdown signaled
    TEST_ASSERT_FALSE(was_handler_called());
    TEST_ASSERT_TRUE(was_shutdown_signal_called());
}

void test_reject_invalid_escape_sequence(void) {
    // Arrange: ESC byte followed by invalid substitute (0xFF)
    uint8_t frame_on_wire[] = { SOF_BYTE, H2T_HEARTBEAT, 0x00, 0x01, ESC_BYTE, 0xFF, 0x00, EOF_BYTE };

    // Act: Process frame with illegal escape sequence
    load_mock_buffer(frame_on_wire, sizeof(frame_on_wire));
    serial_process_data();
    
    // Assert: Verify invalid escape rejected
    TEST_ASSERT_FALSE(was_handler_called());
}

void test_recover_after_corrupted_frame(void) {
    // Arrange: Stream with corrupted frame (no EOF) followed by valid frame
    uint8_t original_payload[] = {0xCC};
    uint8_t checksum = T2H_BOOT_OK + 0x00 + 0x01 + 0xCC;
    uint8_t stream[] = {
        SOF_BYTE, 0x01, 0x02, 0x03, 0x04,
        SOF_BYTE, T2H_BOOT_OK, 0x00, 0x01, 0xCC, checksum, EOF_BYTE
    };
    uint8_t received_payload[1] = {0};

    // Act: Process stream with recovery scenario
    load_mock_buffer(stream, sizeof(stream));
    serial_process_data();
    get_last_payload(received_payload);
    
    // Assert: Verify parser recovered and processed second frame
    TEST_ASSERT_TRUE(was_handler_called());
    TEST_ASSERT_EQUAL(T2H_BOOT_OK, get_last_msg_type());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(original_payload, received_payload, sizeof(original_payload));
}