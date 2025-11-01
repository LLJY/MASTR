#include "unity.h"
#include "mock_pico_sdk.h"
#include <stdbool.h>
#include <string.h>

// Test helpers
extern void reset_mocks(void);

// setUp and tearDown are in test_common.c

// ============================================================================
// Suite: Nonce Generation Tests (UT-33, UT-35)
// ============================================================================

void test_nonce_generation_interface(void) {
    // Arrange: Request random bytes from hardware interface
    uint32_t nonce1, nonce2, nonce3;
    
    // Act: Generate three nonces
    nonce1 = get_rand_32();
    nonce2 = get_rand_32();
    nonce3 = get_rand_32();
    
    // Assert: Verify nonces are non-zero (valid generation)
    TEST_ASSERT_NOT_EQUAL(0, nonce1);
    TEST_ASSERT_NOT_EQUAL(0, nonce2);
    TEST_ASSERT_NOT_EQUAL(0, nonce3);
}

void test_nonce_uniqueness_small_sample(void) {
    // Arrange: Prepare to generate 100 nonces
    uint32_t nonces[100];
    
    // Act: Generate nonces
    for (int i = 0; i < 100; i++) {
        nonces[i] = get_rand_32();
    }
    
    // Assert: Verify all nonces are unique
    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            TEST_ASSERT_NOT_EQUAL_MESSAGE(nonces[i], nonces[j], "Duplicate nonce detected");
        }
    }
}

void test_nonce_uniqueness_large_sample(void) {
    // Arrange: Prepare to generate 1000 nonces for statistical uniqueness test
    #define NONCE_COUNT 1000
    uint32_t nonces[NONCE_COUNT];
    
    // Act: Generate large sample of nonces
    for (int i = 0; i < NONCE_COUNT; i++) {
        nonces[i] = get_rand_32();
    }
    
    // Assert: Verify all 1000 nonces are unique
    int duplicate_count = 0;
    for (int i = 0; i < NONCE_COUNT; i++) {
        for (int j = i + 1; j < NONCE_COUNT; j++) {
            if (nonces[i] == nonces[j]) {
                duplicate_count++;
            }
        }
    }
    
    TEST_ASSERT_EQUAL_MESSAGE(0, duplicate_count, "Duplicates found in 1000 nonces");
}

void test_nonce_distribution_non_zero(void) {
    // Arrange: Generate sample to check for zero values
    uint32_t nonces[50];
    
    // Act: Generate nonces
    for (int i = 0; i < 50; i++) {
        nonces[i] = get_rand_32();
    }
    
    // Assert: Verify no zero values (indicates RNG working)
    for (int i = 0; i < 50; i++) {
        TEST_ASSERT_NOT_EQUAL_MESSAGE(0, nonces[i], "Zero nonce generated");
    }
}