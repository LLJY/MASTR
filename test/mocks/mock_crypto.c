#include "mock_crypto.h"
#include "mock_atca.h"
#include "crypto.h"
#include <string.h>

// Global mock state - now just a thin wrapper over mock_atca state
mock_crypto_state_t mock_crypto_state = {0};

// Mock control functions - these manipulate mock_atca state
void mock_crypto_reset(void) {
    memset(&mock_crypto_state, 0, sizeof(mock_crypto_state));
    mock_atca_reset();

    // Set default behavior
    mock_crypto_state.signature_verify_should_pass = true;
    mock_crypto_state.integrity_check_should_pass = true;
    mock_crypto_state.ecdh_generate_should_fail = false;

    mock_atca_set_verify_result(true);
    mock_atca_set_ecdh_fail(false);
}

void mock_crypto_set_keys(const uint8_t* token_pubkey, const uint8_t* host_pubkey) {
    if (token_pubkey) {
        memcpy(mock_crypto_state.token_permanent_pubkey, token_pubkey, 64);
        mock_atca_set_token_pubkey(token_pubkey);
    }
    if (host_pubkey) {
        memcpy(mock_crypto_state.host_permanent_pubkey, host_pubkey, 64);
        mock_atca_set_host_pubkey(host_pubkey);
    }
}

void mock_crypto_set_golden_hash(const uint8_t* hash) {
    if (hash) {
        memcpy(mock_crypto_state.golden_hash, hash, 32);
        mock_atca_set_golden_hash(hash);
    }
}

void mock_crypto_set_ecdh_fail(bool should_fail) {
    mock_crypto_state.ecdh_generate_should_fail = should_fail;
    mock_atca_set_ecdh_fail(should_fail);
}

void mock_crypto_set_signature_result(bool should_pass) {
    mock_crypto_state.signature_verify_should_pass = should_pass;
    mock_atca_set_verify_result(should_pass);
}

void mock_crypto_set_integrity_result(bool should_pass) {
    mock_crypto_state.integrity_check_should_pass = should_pass;
    mock_atca_set_verify_result(should_pass);
}

void mock_crypto_get_ephemeral_pubkey(uint8_t* pubkey_out) {
    memcpy(pubkey_out, g_mock_atca_state.tempkey_pubkey, 64);
}

void mock_crypto_get_shared_secret(uint8_t* secret_out) {
    // Generate deterministic shared secret for comparison
    for (int i = 0; i < 32; i++) {
        secret_out[i] = 0x40 + i;
    }
}
