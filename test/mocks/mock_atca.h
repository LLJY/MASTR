#ifndef MOCK_ATCA_H
#define MOCK_ATCA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ATCA status codes
typedef uint8_t ATCA_STATUS;
#define ATCA_SUCCESS     0x00
#define ATCA_ZONE_LOCKED 0x01

// ATCA zone definitions
#define ATCA_ZONE_CONFIG 0x00
#define ATCA_ZONE_DATA   0x02

// ATCA key ID definitions
#define ATCA_TEMPKEY_KEYID 0xFFFF

// Mock ATCA state
typedef struct {
    // Slot 0: Token permanent private key (not exposed, only used for signing)
    uint8_t token_permanent_pubkey[64];

    // Slot 8: Host permanent public key (blocks 0-1) + golden hash (block 2)
    uint8_t slot8_data[96];  // 64 bytes pubkey + 32 bytes golden hash

    // TempKey: Ephemeral private key (volatile)
    uint8_t tempkey_privkey[32];
    uint8_t tempkey_pubkey[64];
    bool tempkey_valid;

    // Control flags
    bool signature_verify_should_pass;
    bool ecdh_should_fail;
    bool read_should_fail;
    bool write_should_fail;

    // Counters for verification
    int sign_call_count;
    int verify_call_count;
    int ecdh_call_count;
} mock_atca_state_t;

extern mock_atca_state_t g_mock_atca_state;

// Mock control functions
void mock_atca_reset(void);
void mock_atca_set_token_pubkey(const uint8_t* pubkey);
void mock_atca_set_host_pubkey(const uint8_t* pubkey);
void mock_atca_set_golden_hash(const uint8_t* hash);
void mock_atca_set_verify_result(bool should_pass);
void mock_atca_set_ecdh_fail(bool should_fail);

// ATCA function mocks (these replace the real hardware calls)
ATCA_STATUS atcab_get_pubkey(uint16_t slot, uint8_t* pubkey);
ATCA_STATUS atcab_genkey(uint16_t key_id, uint8_t* pubkey);
ATCA_STATUS atcab_sign(uint16_t slot, const uint8_t* hash, uint8_t* signature);
ATCA_STATUS atcab_verify_extern(const uint8_t* hash, const uint8_t* signature,
                                 const uint8_t* pubkey, bool* is_verified);
ATCA_STATUS atcab_ecdh_tempkey(const uint8_t* peer_pubkey, uint8_t* shared_secret);
ATCA_STATUS atcab_read_zone(uint8_t zone, uint16_t slot, uint8_t block,
                             uint8_t offset, uint8_t* data, uint8_t len);
ATCA_STATUS atcab_write_zone(uint8_t zone, uint16_t slot, uint8_t block,
                              uint8_t offset, const uint8_t* data, uint8_t len);

#endif // MOCK_ATCA_H
