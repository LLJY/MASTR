#include "mock_crypto.h"
#include "crypto.h"
#include <string.h>
#include <stdio.h>

// Global mock state
mock_crypto_state_t mock_crypto_state = {0};

// Mock control functions
void mock_crypto_reset(void) {
    memset(&mock_crypto_state, 0, sizeof(mock_crypto_state));
    // Set default behavior
    mock_crypto_state.signature_verify_should_pass = true;
    mock_crypto_state.integrity_check_should_pass = true;
    mock_crypto_state.ecdh_generate_should_fail = false;
}

void mock_crypto_set_keys(const uint8_t* token_pubkey, const uint8_t* host_pubkey) {
    if (token_pubkey) {
        memcpy(mock_crypto_state.token_permanent_pubkey, token_pubkey, 64);
    }
    if (host_pubkey) {
        memcpy(mock_crypto_state.host_permanent_pubkey, host_pubkey, 64);
    }
}

void mock_crypto_set_golden_hash(const uint8_t* hash) {
    if (hash) {
        memcpy(mock_crypto_state.golden_hash, hash, 32);
    }
}

void mock_crypto_set_ecdh_fail(bool should_fail) {
    mock_crypto_state.ecdh_generate_should_fail = should_fail;
}

void mock_crypto_set_signature_result(bool should_pass) {
    mock_crypto_state.signature_verify_should_pass = should_pass;
}

void mock_crypto_set_integrity_result(bool should_pass) {
    mock_crypto_state.integrity_check_should_pass = should_pass;
}

void mock_crypto_get_ephemeral_pubkey(uint8_t* pubkey_out) {
    memcpy(pubkey_out, mock_crypto_state.ephemeral_pubkey, 64);
}

void mock_crypto_get_shared_secret(uint8_t* secret_out) {
    memcpy(secret_out, mock_crypto_state.shared_secret, 32);
}

// Mock ECDH functions
bool crypto_ecdh_generate_ephemeral_key(uint8_t* ephemeral_pubkey_out) {
    if (mock_crypto_state.ecdh_generate_should_fail) {
        return false;
    }
    
    // Generate deterministic test keys for predictability
    for (int i = 0; i < 32; i++) {
        mock_crypto_state.ephemeral_privkey[i] = 0x10 + i;
    }
    for (int i = 0; i < 64; i++) {
        mock_crypto_state.ephemeral_pubkey[i] = 0x20 + i;
    }
    
    memcpy(ephemeral_pubkey_out, mock_crypto_state.ephemeral_pubkey, 64);
    return true;
}

bool crypto_ecdh_sign_with_permanent_key(const uint8_t* message, size_t message_len, 
                                   uint8_t* signature_out) {
    (void)message;
    (void)message_len;
    
    // Generate deterministic test signature
    for (int i = 0; i < 64; i++) {
        signature_out[i] = 0x30 + i;
    }
    return true;
}

bool crypto_ecdh_read_host_pubkey(uint8_t* host_pubkey_out) {
    memcpy(host_pubkey_out, mock_crypto_state.host_permanent_pubkey, 64);
    return true;
}

bool crypto_ecdh_verify_signature(const uint8_t* message, size_t message_len,
                           const uint8_t* signature, const uint8_t* host_pubkey) {
    (void)message;
    (void)message_len;
    (void)signature;
    (void)host_pubkey;
    
    return mock_crypto_state.signature_verify_should_pass;
}

bool crypto_ecdh_compute_shared_secret(const uint8_t* peer_ephemeral_pubkey,
                                uint8_t* shared_secret_out) {
    (void)peer_ephemeral_pubkey;
    
    // Generate deterministic shared secret
    for (int i = 0; i < 32; i++) {
        mock_crypto_state.shared_secret[i] = 0x40 + i;
    }
    
    memcpy(shared_secret_out, mock_crypto_state.shared_secret, 32);
    return true;
}

bool crypto_ecdh_read_token_pubkey(uint8_t* token_pubkey_out) {
    memcpy(token_pubkey_out, mock_crypto_state.token_permanent_pubkey, 64);
    return true;
}

bool crypto_verify_integrity_challenge(const uint8_t* hash, uint32_t nonce,
                           const uint8_t* signature, const uint8_t* host_pubkey, 
                           bool *result) {
    (void)hash;
    (void)nonce;
    (void)signature;
    (void)host_pubkey;
    
    *result = mock_crypto_state.integrity_check_should_pass;
    return true;  // Operation succeeded
}

bool crypto_get_golden_hash(uint8_t* p_result) {
    memcpy(p_result, mock_crypto_state.golden_hash, 32);
    return true;
}

bool crypto_set_golden_hash(uint8_t* p_hash) {
    memcpy(mock_crypto_state.golden_hash, p_hash, 32);
    return true;
}

// Mock session key derivation (uses simple XOR for testing)
bool crypto_derive_session_key(const uint8_t* shared_secret, uint8_t* session_key_out) {
    // Simple deterministic key derivation for testing
    for (int i = 0; i < 16; i++) {
        session_key_out[i] = shared_secret[i] ^ shared_secret[i + 16];
    }
    return true;
}