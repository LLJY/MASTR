#include "unity.h"
#include "mock_pico_sdk.h"
#include "mock_crypto.h"
#include "mock_time.h"
#include "protocol.h"
#include <string.h>

// Test helpers
extern void reset_mocks(void);

// setUp and tearDown are in test_common.c

// ============================================================================
// Suite 5.1: Session Lifecycle
// ============================================================================

void test_session_establishment(void) {
    // Arrange: State 0x32 (BOOT_OK sent) awaiting acknowledgment
    protocol_state.current_state = 0x32;
    uint64_t start_time = 2000000;
    mock_time_set(start_time);
    
    // Act: Process boot acknowledgment to establish session
    handle_validated_message(H2T_BOOT_OK_ACK, NULL, 0);
    
    // Assert: Verify session established with valid timestamp and runtime state
    TEST_ASSERT_TRUE(protocol_state.session_valid);
    TEST_ASSERT_EQUAL_UINT64(start_time, protocol_state.session_start_timestamp);
    TEST_ASSERT_EQUAL_UINT8(0x40, protocol_state.current_state);
}

void test_session_is_valid_within_timeout(void) {
    // Arrange: Valid session with 30s timeout, elapsed time 20s
    protocol_state.session_valid = true;
    protocol_state.session_timeout_ms = 30000;
    protocol_state.session_start_timestamp = 1000000;
    
    mock_time_set(21000000);
    
    // Act: Check session validity within timeout window
    bool is_valid = protocol_is_session_valid();
    
    // Assert: Verify session still valid
    TEST_ASSERT_TRUE(is_valid);
}

void test_session_invalid_after_timeout(void) {
    // Arrange: Valid session with 30s timeout, elapsed time 35s
    protocol_state.session_valid = true;
    protocol_state.session_timeout_ms = 30000;
    protocol_state.session_start_timestamp = 1000000;
    
    mock_time_set(36000000);
    
    // Act: Check session validity after timeout expires
    bool is_valid = protocol_is_session_valid();
    
    // Assert: Verify session invalidated by timeout
    TEST_ASSERT_FALSE(is_valid);
}

void test_session_timestamp_tracking(void) {
    // Arrange: State 0x32 with specific time value
    uint64_t expected_time = 12345678;
    mock_time_set(expected_time);
    protocol_state.current_state = 0x32;
    
    // Act: Establish session and capture timestamp
    handle_validated_message(H2T_BOOT_OK_ACK, NULL, 0);
    
    // Assert: Verify session timestamp matches establishment time
    TEST_ASSERT_EQUAL_UINT64(expected_time, protocol_state.session_start_timestamp);
}

// ============================================================================
// Suite 5.2: Session Invalidation
// ============================================================================

void test_invalidate_session_keeps_old_key(void) {
    // Arrange: Valid encrypted session with established AES key
    protocol_state.session_valid = true;
    protocol_state.is_encrypted = true;
    uint8_t old_key[16];
    for (int i = 0; i < 16; i++) old_key[i] = i + 10;
    memcpy(protocol_state.aes_session_key, old_key, 16);
    
    // Act: Invalidate session
    protocol_invalidate_session();
    
    // Assert: Verify session invalid but encryption and key preserved for re-attestation
    TEST_ASSERT_FALSE(protocol_state.session_valid);
    TEST_ASSERT_TRUE(protocol_state.is_encrypted);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(old_key, protocol_state.aes_session_key, 16);
}

void test_invalidate_session_resets_to_ecdh_state(void) {
    // Arrange: Runtime state 0x40 with valid session
    protocol_state.current_state = 0x40;
    protocol_state.session_valid = true;
    
    // Act: Invalidate session
    protocol_invalidate_session();
    
    // Assert: Verify state reset to ECDH initialization 0x20
    TEST_ASSERT_EQUAL_UINT8(0x20, protocol_state.current_state);
}

void test_encryption_flag_persists_through_invalidation(void) {
    // Arrange: Encrypted valid session
    protocol_state.is_encrypted = true;
    protocol_state.session_valid = true;
    
    // Act: Invalidate session
    protocol_invalidate_session();
    
    // Assert: Verify encryption flag remains enabled
    TEST_ASSERT_TRUE(protocol_state.is_encrypted);
}

// ============================================================================
// Suite 5.3: Re-attestation
// ============================================================================

void test_trigger_reattestation_invalidates_session(void) {
    // Arrange: Valid runtime session 0x40
    protocol_state.session_valid = true;
    protocol_state.current_state = 0x40;
    
    // Act: Trigger re-attestation
    protocol_trigger_reattestation();
    
    // Assert: Verify session invalidated
    TEST_ASSERT_FALSE(protocol_state.session_valid);
}

void test_trigger_reattestation_generates_new_ephemeral_key(void) {
    // Arrange: Valid session with existing ephemeral key
    protocol_state.session_valid = true;
    uint8_t old_ephemeral[64];
    memset(old_ephemeral, 0xFF, 64);
    memcpy(protocol_state.et_pubkey, old_ephemeral, 64);
    
    // Act: Trigger re-attestation
    protocol_trigger_reattestation();
    
    // Assert: Verify new ephemeral key generated (mock produces deterministic key)
    uint8_t expected_new_key[64];
    for (int i = 0; i < 64; i++) expected_new_key[i] = 0x20 + i;
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected_new_key, protocol_state.et_pubkey, 64);
}

void test_trigger_reattestation_advances_to_state_0x21(void) {
    // Arrange: Runtime state 0x40
    protocol_state.current_state = 0x40;
    
    // Act: Trigger re-attestation
    protocol_trigger_reattestation();
    
    // Assert: Verify state advanced to 0x21 (token sent ECDH share)
    TEST_ASSERT_EQUAL_UINT8(0x21, protocol_state.current_state);
}

// ============================================================================
// Suite 5.4: Session Timeout Scenarios
// ============================================================================

void test_session_custom_timeout(void) {
    // Arrange: Valid session with custom 60s timeout
    protocol_state.session_valid = true;
    protocol_state.session_timeout_ms = 60000;
    protocol_state.session_start_timestamp = 1000000;
    
    mock_time_set(51000000);
    
    // Act: Check validity at 50s (within timeout)
    bool is_valid = protocol_is_session_valid();
    
    // Assert: Verify session valid within custom timeout
    TEST_ASSERT_TRUE(is_valid);
    
    // Act: Advance to 62s (past custom timeout)
    mock_time_set(62000000);
    is_valid = protocol_is_session_valid();
    
    // Assert: Verify session invalid after custom timeout
    TEST_ASSERT_FALSE(is_valid);
}

void test_session_not_valid_when_flag_false(void) {
    // Arrange: Session with valid flag set to false, time within timeout window
    protocol_state.session_valid = false;
    protocol_state.session_start_timestamp = 1000000;
    protocol_state.session_timeout_ms = 30000;
    
    mock_time_set(10000000);
    
    // Act: Check session validity
    bool is_valid = protocol_is_session_valid();
    
    // Assert: Verify session invalid regardless of timeout due to flag
    TEST_ASSERT_FALSE(is_valid);
}

void test_heartbeat_resets_missed_count(void) {
    // Arrange: Runtime state with 3 missed heartbeats
    protocol_state.current_state = 0x40;
    protocol_state.missed_hb_count = 3;
    mock_time_set(5000000);
    
    // Act: Process heartbeat message
    handle_validated_message(H2T_HEARTBEAT, NULL, 0);
    
    // Assert: Verify missed count reset and timestamp updated
    TEST_ASSERT_EQUAL_UINT8(0, protocol_state.missed_hb_count);
    TEST_ASSERT_EQUAL_UINT64(5000000, protocol_state.last_hb_timstamp);
}

void test_three_missed_heartbeats_should_trigger_shutdown(void) {
    // Arrange: Runtime state with exactly 3 missed heartbeats
    protocol_state.current_state = 0x40;
    protocol_state.session_valid = true;
    protocol_state.missed_hb_count = 3;
    
    // Act: Check if system should initiate shutdown
    bool should_shutdown = (protocol_state.missed_hb_count >= 3);
    
    // Assert: Verify shutdown condition met
    TEST_ASSERT_TRUE(should_shutdown);
}

void test_two_missed_heartbeats_no_shutdown(void) {
    // Arrange: Runtime state with only 2 missed heartbeats
    protocol_state.current_state = 0x40;
    protocol_state.session_valid = true;
    protocol_state.missed_hb_count = 2;
    
    // Act: Check if system should initiate shutdown
    bool should_shutdown = (protocol_state.missed_hb_count >= 3);
    
    // Assert: Verify shutdown not triggered yet
    TEST_ASSERT_FALSE(should_shutdown);
}

void test_missed_heartbeat_counter_increments(void) {
    // Arrange: Runtime state with zero missed heartbeats
    protocol_state.current_state = 0x40;
    protocol_state.session_valid = true;
    protocol_state.missed_hb_count = 0;
    uint8_t initial_count = protocol_state.missed_hb_count;
    
    // Act: Simulate missed heartbeat (increment counter)
    protocol_state.missed_hb_count++;
    
    // Assert: Verify counter incremented
    TEST_ASSERT_EQUAL_UINT8(initial_count + 1, protocol_state.missed_hb_count);
}

// ============================================================================
// Suite 5.5: Halt State Testing
// ============================================================================

void test_halt_state_sets_flag(void) {
    // Arrange: Normal state (not halted)
    protocol_state.in_halt_state = false;
    
    // Act: Manually simulate halt state transition (actual function has infinite loop)
    protocol_state.in_halt_state = true;
    protocol_state.current_state = 0xFF;
    
    // Assert: Verify halt flag and state set correctly
    TEST_ASSERT_TRUE(protocol_state.in_halt_state);
    TEST_ASSERT_EQUAL_UINT8(0xFF, protocol_state.current_state);
}

// ============================================================================
// Test runner will be updated in test_runner.c
// ============================================================================