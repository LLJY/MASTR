#include "unity.h"

// Forward declarations of all test functions
void setUp(void);
void tearDown(void);

// Suite 1: Sending
void test_send_simple_packet(void);
void test_send_with_all_special_bytes_in_payload(void);
void test_send_zero_length_payload(void);

// Suite 2: Receiving
void test_receive_simple_packet(void);
void test_receive_stuffed_packet(void);
void test_receive_zero_length_packet(void);
void test_ignore_bytes_before_SOF(void);

// Suite 3: Error Handling
void test_reject_bad_checksum(void);
void test_reject_bad_length(void);
void test_reject_invalid_escape_sequence(void);
void test_recover_after_corrupted_frame(void);


// Main function for the test executable
int main(void) {
    UNITY_BEGIN();

    // Suite 1
    RUN_TEST(test_send_simple_packet);
    RUN_TEST(test_send_with_all_special_bytes_in_payload);
    RUN_TEST(test_send_zero_length_payload);
    
    // Suite 2
    RUN_TEST(test_receive_simple_packet);
    RUN_TEST(test_receive_stuffed_packet);
    RUN_TEST(test_receive_zero_length_packet);
    RUN_TEST(test_ignore_bytes_before_SOF);

    // Suite 3
    RUN_TEST(test_reject_bad_checksum);
    RUN_TEST(test_reject_bad_length);
    RUN_TEST(test_reject_invalid_escape_sequence);
    RUN_TEST(test_recover_after_corrupted_frame);

    return UNITY_END();
}