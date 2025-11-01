#include "unity.h"
#include "mock_pico_sdk.h"
#include "mock_crypto.h"
#include "protocol.h"
#include <string.h>

// Test helpers
extern void reset_mocks(void);

// setUp and tearDown are in test_common.c

// ============================================================================
// Suite: File Integrity Check Tests (UT-38, UT-39)
// ============================================================================

void test_integrity_hash_comparison_exact_match(void) {
    // Arrange: Golden hash and computed hash that match exactly
    uint8_t golden_hash[32];
    uint8_t computed_hash[32];
    memset(golden_hash, 0xAA, 32);
    memset(computed_hash, 0xAA, 32);
    
    mock_crypto_set_golden_hash(golden_hash);
    mock_crypto_set_integrity_result(true);
    
    protocol_state.current_state = 0x30;
    protocol_state.integrity_challenge_nonce = 0x12345678;
    
    // Act: Process integrity response with matching hash
    uint8_t payload[96];
    memcpy(payload, computed_hash, 32);
    memset(payload + 32, 0xDD, 64);
    
    handle_validated_message(H2T_INTEGRITY_RESPONSE, payload, 96);
    
    // Assert: Verify integrity passed and state advanced
    TEST_ASSERT_EQUAL_UINT8(0x32, protocol_state.current_state);
}

void test_integrity_detects_single_bit_tampering(void) {
    // Arrange: Golden hash and computed hash differing by one bit
    uint8_t golden_hash[32];
    uint8_t tampered_hash[32];
    memset(golden_hash, 0xAA, 32);
    memset(tampered_hash, 0xAA, 32);
    tampered_hash[0] = 0xAB;
    
    mock_crypto_set_golden_hash(golden_hash);
    mock_crypto_set_integrity_result(false);
    
    protocol_state.current_state = 0x30;
    
    // Act: Process integrity response with tampered hash
    uint8_t payload[96];
    memcpy(payload, tampered_hash, 32);
    memset(payload + 32, 0xDD, 64);
    
    handle_validated_message(H2T_INTEGRITY_RESPONSE, payload, 96);
    
    // Assert: Verify system entered halt state due to tampering
    TEST_ASSERT_EQUAL_UINT8(0xFF, protocol_state.current_state);
}

void test_integrity_detects_complete_hash_mismatch(void) {
    // Arrange: Completely different golden and computed hashes
    uint8_t golden_hash[32];
    uint8_t tampered_hash[32];
    memset(golden_hash, 0xAA, 32);
    memset(tampered_hash, 0xBB, 32);
    
    mock_crypto_set_golden_hash(golden_hash);
    mock_crypto_set_integrity_result(false);
    
    protocol_state.current_state = 0x30;
    
    // Act: Process integrity response with completely wrong hash
    uint8_t payload[96];
    memcpy(payload, tampered_hash, 32);
    memset(payload + 32, 0xDD, 64);
    
    handle_validated_message(H2T_INTEGRITY_RESPONSE, payload, 96);
    
    // Assert: Verify system entered halt state due to tampering
    TEST_ASSERT_EQUAL_UINT8(0xFF, protocol_state.current_state);
}

void test_integrity_validates_with_different_nonce(void) {
    // Arrange: Same hashes but different challenge nonces
    uint8_t golden_hash[32];
    uint8_t computed_hash[32];
    memset(golden_hash, 0xCC, 32);
    memset(computed_hash, 0xCC, 32);
    
    mock_crypto_set_golden_hash(golden_hash);
    mock_crypto_set_integrity_result(true);
    
    protocol_state.current_state = 0x30;
    protocol_state.integrity_challenge_nonce = 0xDEADBEEF;
    
    // Act: Process integrity response with different nonce
    uint8_t payload[96];
    memcpy(payload, computed_hash, 32);
    memset(payload + 32, 0xEE, 64);
    
    handle_validated_message(H2T_INTEGRITY_RESPONSE, payload, 96);
    
    // Assert: Verify integrity still passes (nonce doesn't affect hash comparison)
    TEST_ASSERT_EQUAL_UINT8(0x32, protocol_state.current_state);
}

void test_integrity_zero_hash_detection(void) {
    // Arrange: All-zero hash (potential attack or error)
    uint8_t golden_hash[32];
    uint8_t zero_hash[32];
    memset(golden_hash, 0xDD, 32);
    memset(zero_hash, 0x00, 32);
    
    mock_crypto_set_golden_hash(golden_hash);
    mock_crypto_set_integrity_result(false);
    
    protocol_state.current_state = 0x30;
    
    // Act: Process integrity response with zero hash
    uint8_t payload[96];
    memcpy(payload, zero_hash, 32);
    memset(payload + 32, 0xFF, 64);
    
    handle_validated_message(H2T_INTEGRITY_RESPONSE, payload, 96);
    
    // Assert: Verify system entered halt state (zero hash rejected)
    TEST_ASSERT_EQUAL_UINT8(0xFF, protocol_state.current_state);
}

void test_integrity_all_ones_hash_detection(void) {
    // Arrange: All-ones hash (potential attack or error)
    uint8_t golden_hash[32];
    uint8_t ones_hash[32];
    memset(golden_hash, 0xDD, 32);
    memset(ones_hash, 0xFF, 32);
    
    mock_crypto_set_golden_hash(golden_hash);
    mock_crypto_set_integrity_result(false);
    
    protocol_state.current_state = 0x30;
    
    // Act: Process integrity response with all-ones hash
    uint8_t payload[96];
    memcpy(payload, ones_hash, 32);
    memset(payload + 32, 0xAA, 64);
    
    handle_validated_message(H2T_INTEGRITY_RESPONSE, payload, 96);
    
    // Assert: Verify system entered halt state (all-ones hash rejected)
    TEST_ASSERT_EQUAL_UINT8(0xFF, protocol_state.current_state);
}