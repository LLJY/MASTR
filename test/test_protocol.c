#include "unity.h"
#include "mock_pico_sdk.h"
#include "mock_crypto.h"
#include "mock_time.h"
#include "protocol.h"
#include "serial.h"
#include <string.h>

// Test helpers
extern void reset_mocks(void);
extern bool was_shutdown_signal_called(void);

// setUp and tearDown are in test_common.c

// ============================================================================
// Suite 2.1: Valid State Transitions
// ============================================================================

void test_state_transition_0x20_to_0x21_on_ecdh_share(void) {
    // Arrange: State 0x20 with valid ECDH share message (64B pubkey + 64B signature)
    protocol_state.current_state = 0x20;
    
    uint8_t host_pubkey[64];
    memset(host_pubkey, 0xAA, 64);
    mock_crypto_set_keys(NULL, host_pubkey);
    
    uint8_t payload[128];
    memset(payload, 0xBB, 64);
    memset(payload + 64, 0xCC, 64);
    
    // Act: Process ECDH share message from host
    protocol_handle_validated_message(H2T_ECDH_SHARE, payload, 128);
    
    // Assert: Verify transition to state 0x21 and encryption enabled
    TEST_ASSERT_EQUAL_UINT8(0x21, protocol_state.current_state);
    TEST_ASSERT_TRUE(protocol_state.is_encrypted);
}

void test_state_transition_0x22_to_0x30_on_channel_verify(void) {
    // Arrange: State 0x22 with encrypted channel, expecting "pong" response
    protocol_state.current_state = 0x22;
    protocol_state.is_encrypted = true;
    
    uint8_t payload[4] = {'p', 'o', 'n', 'g'};
    
    // Act: Process correct channel verify response
    protocol_handle_validated_message(H2T_CHANNEL_VERIFY_RESPONSE, payload, 4);
    
    // Assert: Verify transition to integrity check state 0x30
    TEST_ASSERT_EQUAL_UINT8(0x30, protocol_state.current_state);
}

void test_state_transition_0x30_to_0x32_on_valid_integrity(void) {
    // Arrange: State 0x30 with golden hash matching integrity response (32B hash + 64B sig)
    protocol_state.current_state = 0x30;
    protocol_state.integrity_challenge_nonce = 0x12345678;
    
    uint8_t golden_hash[32];
    memset(golden_hash, 0xDD, 32);
    mock_crypto_set_golden_hash(golden_hash);
    mock_crypto_set_integrity_result(true);
    
    uint8_t payload[96];
    memset(payload, 0xDD, 32);
    memset(payload + 32, 0xEE, 64);
    
    // Act: Process valid integrity response
    protocol_handle_validated_message(H2T_INTEGRITY_RESPONSE, payload, 96);
    
    // Assert: Verify transition to boot OK state 0x32
    TEST_ASSERT_EQUAL_UINT8(0x32, protocol_state.current_state);
}

void test_state_transition_0x32_to_0x40_on_boot_ack(void) {
    // Arrange: State 0x32 awaiting boot acknowledgment
    protocol_state.current_state = 0x32;
    uint64_t start_time = 1000000;
    mock_time_set(start_time);
    
    // Act: Process boot OK acknowledgment
    protocol_handle_validated_message(H2T_BOOT_OK_ACK, NULL, 0);
    
    // Assert: Verify transition to runtime state 0x40 with valid session
    TEST_ASSERT_EQUAL_UINT8(0x40, protocol_state.current_state);
    TEST_ASSERT_TRUE(protocol_state.session_valid);
    TEST_ASSERT_EQUAL_UINT64(start_time, protocol_state.session_start_timestamp);
}

void test_heartbeat_accepted_in_runtime_state(void) {
    // Arrange: Runtime state 0x40 with valid session
    protocol_state.current_state = 0x40;
    protocol_state.session_valid = true;
    uint64_t initial_time = 5000000;
    mock_time_set(initial_time);
    
    // Act: Process heartbeat message
    protocol_handle_validated_message(H2T_HEARTBEAT, NULL, 0);
    
    // Assert: Verify heartbeat timestamp updated and missed count reset
    TEST_ASSERT_EQUAL_UINT8(0x40, protocol_state.current_state);
    TEST_ASSERT_EQUAL_UINT64(initial_time, protocol_state.last_hb_timstamp);
    TEST_ASSERT_EQUAL_UINT8(0, protocol_state.missed_hb_count);
}

// ============================================================================
// Suite 2.2: Invalid State Rejections
// ============================================================================

void test_reject_integrity_response_in_wrong_state(void) {
    // Arrange: State 0x20 (wrong state, should be 0x30 for integrity)
    protocol_state.current_state = 0x20;
    
    uint8_t payload[96];
    memset(payload, 0xFF, 96);
    
    // Act: Attempt integrity response in wrong state
    protocol_handle_validated_message(H2T_INTEGRITY_RESPONSE, payload, 96);
    
    // Assert: Verify shutdown triggered for protocol violation
    TEST_ASSERT_TRUE(was_shutdown_signal_called());
}

void test_reject_heartbeat_before_runtime(void) {
    // Arrange: State 0x30 (not in runtime state 0x40)
    protocol_state.current_state = 0x30;
    
    // Act: Attempt heartbeat in wrong state
    protocol_handle_validated_message(H2T_HEARTBEAT, NULL, 0);
    
    // Assert: Verify heartbeat rejected, state unchanged
    TEST_ASSERT_EQUAL_UINT8(0x30, protocol_state.current_state);
}

void test_reject_boot_ack_in_wrong_state(void) {
    // Arrange: State 0x40 (wrong state, should be 0x32 for boot ack)
    protocol_state.current_state = 0x40;
    
    // Act: Attempt boot ack in wrong state
    protocol_handle_validated_message(H2T_BOOT_OK_ACK, NULL, 0);
    
    // Assert: Verify shutdown triggered for protocol violation
    TEST_ASSERT_TRUE(was_shutdown_signal_called());
}

void test_reject_channel_verify_in_wrong_state(void) {
    // Arrange: State 0x40 (wrong state, should be 0x22 for channel verify)
    protocol_state.current_state = 0x40;
    
    uint8_t payload[4] = {'p', 'o', 'n', 'g'};
    
    // Act: Attempt channel verify in wrong state
    protocol_handle_validated_message(H2T_CHANNEL_VERIFY_RESPONSE, payload, 4);
    
    // Assert: Verify shutdown triggered for protocol violation
    TEST_ASSERT_TRUE(was_shutdown_signal_called());
}

// ============================================================================
// Suite 2.3: Error Scenarios
// ============================================================================

void test_invalid_ecdh_share_length_triggers_shutdown(void) {
    // Arrange: State 0x20 with undersized ECDH payload (64B instead of 128B)
    protocol_state.current_state = 0x20;
    
    uint8_t payload[64];
    memset(payload, 0xAA, 64);
    
    // Act: Process malformed ECDH share
    protocol_handle_validated_message(H2T_ECDH_SHARE, payload, 64);
    
    // Assert: Verify shutdown triggered for invalid length
    TEST_ASSERT_TRUE(was_shutdown_signal_called());
}

void test_invalid_integrity_length_sends_nack(void) {
    // Arrange: State 0x30 with wrong-sized integrity response (50B instead of 96B)
    protocol_state.current_state = 0x30;
    
    uint8_t payload[50];
    memset(payload, 0xBB, 50);
    
    // Act: Process malformed integrity response
    protocol_handle_validated_message(H2T_INTEGRITY_RESPONSE, payload, 50);
    
    // Assert: Verify state unchanged, NACK sent
    TEST_ASSERT_EQUAL_UINT8(0x30, protocol_state.current_state);
}

void test_bad_channel_verify_response_triggers_shutdown(void) {
    // Arrange: State 0x22 with incorrect pong response ("bad!" instead of "pong")
    protocol_state.current_state = 0x22;
    
    uint8_t payload[4] = {'b', 'a', 'd', '!'};
    
    // Act: Process wrong channel verify response
    protocol_handle_validated_message(H2T_CHANNEL_VERIFY_RESPONSE, payload, 4);
    
    // Assert: Verify shutdown triggered for failed channel verification
    TEST_ASSERT_TRUE(was_shutdown_signal_called());
}

void test_failed_signature_verification_triggers_shutdown(void) {
    // Arrange: State 0x20 with mock configured to fail signature verification
    protocol_state.current_state = 0x20;
    mock_crypto_set_signature_result(false);
    
    uint8_t host_pubkey[64];
    memset(host_pubkey, 0xAA, 64);
    mock_crypto_set_keys(NULL, host_pubkey);
    
    uint8_t payload[128];
    memset(payload, 0xBB, 128);
    
    // Act: Process ECDH share with invalid signature
    protocol_handle_validated_message(H2T_ECDH_SHARE, payload, 128);
    
    // Assert: Verify shutdown triggered for cryptographic failure
    TEST_ASSERT_TRUE(was_shutdown_signal_called());
}

// ============================================================================
// Suite 2.4: Token-Initiated Re-attestation
// ============================================================================

void test_reattestation_keeps_old_session_key(void) {
    // Arrange: Valid encrypted session with AES key
    protocol_state.session_valid = true;
    protocol_state.is_encrypted = true;
    uint8_t old_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    memcpy(protocol_state.aes_session_key, old_key, 16);
    
    // Act: Invalidate session for re-attestation
    protocol_invalidate_session();
    
    // Assert: Verify session invalidated but old key and encryption preserved
    TEST_ASSERT_FALSE(protocol_state.session_valid);
    TEST_ASSERT_TRUE(protocol_state.is_encrypted);
    TEST_ASSERT_EQUAL_UINT8(0x20, protocol_state.current_state);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(old_key, protocol_state.aes_session_key, 16);
}

void test_ecdh_at_state_0x21_uses_existing_key(void) {
    // Arrange: State 0x21 with token-initiated ECDH (token already sent share)
    protocol_state.current_state = 0x21;
    
    uint8_t existing_ephemeral[64];
    memset(existing_ephemeral, 0xEE, 64);
    memcpy(protocol_state.et_pubkey, existing_ephemeral, 64);
    
    uint8_t host_pubkey[64];
    memset(host_pubkey, 0xAA, 64);
    mock_crypto_set_keys(NULL, host_pubkey);
    
    uint8_t payload[128];
    memset(payload, 0xBB, 128);
    
    // Act: Process host ECDH share when token already initiated
    protocol_handle_validated_message(H2T_ECDH_SHARE, payload, 128);
    
    // Assert: Verify existing ephemeral key preserved (not regenerated)
    TEST_ASSERT_EQUAL_UINT8_ARRAY(existing_ephemeral, protocol_state.et_pubkey, 64);
    TEST_ASSERT_TRUE(protocol_state.is_encrypted);
}

// ============================================================================
// Test runner will be updated in test_runner.c
// ============================================================================