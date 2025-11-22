#include "mock_atca.h"
#include <string.h>

// Global mock state
mock_atca_state_t g_mock_atca_state = {0};

void mock_atca_reset(void) {
    memset(&g_mock_atca_state, 0, sizeof(g_mock_atca_state));
    g_mock_atca_state.signature_verify_should_pass = true;
    g_mock_atca_state.ecdh_should_fail = false;
    g_mock_atca_state.read_should_fail = false;
    g_mock_atca_state.write_should_fail = false;
    g_mock_atca_state.tempkey_valid = false;
}

void mock_atca_set_token_pubkey(const uint8_t* pubkey) {
    if (pubkey) {
        memcpy(g_mock_atca_state.token_permanent_pubkey, pubkey, 64);
    }
}

void mock_atca_set_host_pubkey(const uint8_t* pubkey) {
    if (pubkey) {
        memcpy(g_mock_atca_state.slot8_data, pubkey, 64);
    }
}

void mock_atca_set_golden_hash(const uint8_t* hash) {
    if (hash) {
        memcpy(g_mock_atca_state.slot8_data + 64, hash, 32);
    }
}

void mock_atca_set_verify_result(bool should_pass) {
    g_mock_atca_state.signature_verify_should_pass = should_pass;
}

void mock_atca_set_ecdh_fail(bool should_fail) {
    g_mock_atca_state.ecdh_should_fail = should_fail;
}

// Get public key from slot
ATCA_STATUS atcab_get_pubkey(uint16_t slot, uint8_t* pubkey) {
    if (!pubkey) return 0x01;

    if (slot == 0) {
        // Return token permanent public key
        memcpy(pubkey, g_mock_atca_state.token_permanent_pubkey, 64);
        return ATCA_SUCCESS;
    }

    return 0x01; // Unsupported slot
}

// Generate ephemeral keypair in TempKey
ATCA_STATUS atcab_genkey(uint16_t key_id, uint8_t* pubkey) {
    if (!pubkey) return 0x01;

    if (key_id == ATCA_TEMPKEY_KEYID) {
        // Generate deterministic ephemeral key for testing
        for (int i = 0; i < 32; i++) {
            g_mock_atca_state.tempkey_privkey[i] = 0x10 + i;
        }
        for (int i = 0; i < 64; i++) {
            g_mock_atca_state.tempkey_pubkey[i] = 0x20 + i;
        }
        g_mock_atca_state.tempkey_valid = true;

        memcpy(pubkey, g_mock_atca_state.tempkey_pubkey, 64);
        return ATCA_SUCCESS;
    }

    return 0x01; // Unsupported key_id
}

// Sign hash with private key in slot
ATCA_STATUS atcab_sign(uint16_t slot, const uint8_t* hash, uint8_t* signature) {
    if (!hash || !signature) return 0x01;

    g_mock_atca_state.sign_call_count++;

    if (slot == 0) {
        // Generate deterministic signature for testing
        // In real hardware, this would use the private key in slot 0
        for (int i = 0; i < 64; i++) {
            signature[i] = 0x30 + (i % 32);
        }
        return ATCA_SUCCESS;
    }

    return 0x01; // Unsupported slot
}

// Verify signature using external public key
ATCA_STATUS atcab_verify_extern(const uint8_t* hash, const uint8_t* signature,
                                 const uint8_t* pubkey, bool* is_verified) {
    if (!hash || !signature || !pubkey || !is_verified) return 0x01;

    g_mock_atca_state.verify_call_count++;

    // Return configured verification result
    *is_verified = g_mock_atca_state.signature_verify_should_pass;
    return ATCA_SUCCESS;
}

// Compute ECDH shared secret using TempKey
ATCA_STATUS atcab_ecdh_tempkey(const uint8_t* peer_pubkey, uint8_t* shared_secret) {
    if (!peer_pubkey || !shared_secret) return 0x01;

    g_mock_atca_state.ecdh_call_count++;

    if (g_mock_atca_state.ecdh_should_fail) {
        return 0x01;
    }

    if (!g_mock_atca_state.tempkey_valid) {
        return 0x01; // TempKey not initialized
    }

    // Generate deterministic shared secret for testing
    // In real hardware, this would perform ECDH: tempkey_privkey * peer_pubkey
    for (int i = 0; i < 32; i++) {
        shared_secret[i] = 0x40 + i;
    }

    return ATCA_SUCCESS;
}

// Read data from zone/slot
ATCA_STATUS atcab_read_zone(uint8_t zone, uint16_t slot, uint8_t block,
                             uint8_t offset, uint8_t* data, uint8_t len) {
    if (!data) return 0x01;

    if (g_mock_atca_state.read_should_fail) {
        return 0x01;
    }

    if (zone == ATCA_ZONE_DATA && slot == 8) {
        // Read from slot 8: host pubkey (blocks 0-1) or golden hash (block 2)
        size_t read_offset = block * 32 + offset;
        if (read_offset + len <= sizeof(g_mock_atca_state.slot8_data)) {
            memcpy(data, g_mock_atca_state.slot8_data + read_offset, len);
            return ATCA_SUCCESS;
        }
    }

    return 0x01; // Unsupported zone/slot
}

// Write data to zone/slot
ATCA_STATUS atcab_write_zone(uint8_t zone, uint16_t slot, uint8_t block,
                              uint8_t offset, const uint8_t* data, uint8_t len) {
    if (!data) return 0x01;

    if (g_mock_atca_state.write_should_fail) {
        return 0x01;
    }

    if (zone == ATCA_ZONE_DATA && slot == 8) {
        // Write to slot 8: host pubkey (blocks 0-1) or golden hash (block 2)
        size_t write_offset = block * 32 + offset;
        if (write_offset + len <= sizeof(g_mock_atca_state.slot8_data)) {
            memcpy(g_mock_atca_state.slot8_data + write_offset, data, len);
            return ATCA_SUCCESS;
        }
    }

    return 0x01; // Unsupported zone/slot
}
