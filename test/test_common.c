#include "unity.h"
#include "mock_pico_sdk.h"
#include "mock_crypto.h"
#include "mock_time.h"
#include "protocol.h"
#include <string.h>

// Common setUp for all tests
void setUp(void) {
    reset_mocks();
    mock_crypto_reset();
    mock_time_reset();
    
    // Reset protocol state
    memset(&protocol_state, 0, sizeof(protocol_state));
    protocol_state.current_state = 0x20;  // Start at ECDH state
    protocol_state.session_timeout_ms = 30000;
}

// Common tearDown for all tests
void tearDown(void) {
    // Cleanup if needed
}