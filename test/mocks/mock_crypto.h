#ifndef MOCK_CRYPTO_H
#define MOCK_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Mock ATCA types and constants
typedef uint8_t ATCA_STATUS;
#define ATCA_SUCCESS 0x00
#define ATCA_ZONE_DATA 0x02

// Mock ATECC608A state
typedef struct {
    // Permanent keys
    uint8_t token_permanent_pubkey[64];
    uint8_t host_permanent_pubkey[64];
    
    // Ephemeral keys (session-specific)
    uint8_t ephemeral_privkey[32];
    uint8_t ephemeral_pubkey[64];
    
    // Shared secret from ECDH
    uint8_t shared_secret[32];
    
    // Golden hash for integrity verification
    uint8_t golden_hash[32];
    
    // Behavior control flags
    bool ecdh_generate_should_fail;
    bool signature_verify_should_pass;
    bool integrity_check_should_pass;
} mock_crypto_state_t;

// Global mock state
extern mock_crypto_state_t mock_crypto_state;

// Mock control functions
void mock_crypto_reset(void);
void mock_crypto_set_keys(const uint8_t* token_pubkey, const uint8_t* host_pubkey);
void mock_crypto_set_golden_hash(const uint8_t* hash);
void mock_crypto_set_ecdh_fail(bool should_fail);
void mock_crypto_set_signature_result(bool should_pass);
void mock_crypto_set_integrity_result(bool should_pass);

// Get computed values for verification
void mock_crypto_get_ephemeral_pubkey(uint8_t* pubkey_out);
void mock_crypto_get_shared_secret(uint8_t* secret_out);

// Mock SHA256 function
bool compute_sha256(const uint8_t* message, size_t message_len, uint8_t* hash_out);

// Mock ATCA functions
ATCA_STATUS atcab_read_zone(uint8_t zone, uint16_t slot, uint8_t block,
                             uint8_t offset, uint8_t* data, uint8_t len);
ATCA_STATUS atcab_write_zone(uint8_t zone, uint16_t slot, uint8_t block,
                              uint8_t offset, const uint8_t* data, uint8_t len);

#endif // MOCK_CRYPTO_H