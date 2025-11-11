#ifndef CRYPT_H
#define CRYPT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "protocol.h"

// AES-128 key size
#define AES_KEY_SIZE 16

// AES block size (always 16 bytes for AES-128)
#define AES_BLOCK_SIZE 16

// GCM IV/Nonce size (recommended 12 bytes for GCM)
#define GCM_IV_SIZE 12

// GCM Authentication Tag size (16 bytes)
#define GCM_TAG_SIZE 16

// Maximum encrypted payload overhead: IV (12) + Tag (16) = 28 bytes
#define ENCRYPTION_OVERHEAD (GCM_IV_SIZE + GCM_TAG_SIZE)

/**
 * @brief Initialize the cryptographic subsystem
 * 
 * Sets up hardware acceleration (RP2350) or software fallback (RP2040)
 * 
 * @return true if initialization successful, false otherwise
 */
bool crypto_init(void);

/**
 * @brief Check if token is provisioned (has valid host pubkey)
 * 
 * Provisioning is complete when the host's permanent public key has been written to Slot 8.
 * 
 */

/**
 * @brief Encrypt a frame payload using AES-128-GCM
 * 
 * Encrypts the payload and adds authentication tag for integrity.
 * Output format: [IV (12 bytes)][Ciphertext (len bytes)][Tag (16 bytes)]
 * 
 * @param plaintext Input plaintext data
 * @param plaintext_len Length of plaintext
 * @param key AES-128 key (16 bytes)
 * @param ciphertext_out Output buffer (must be >= plaintext_len + ENCRYPTION_OVERHEAD)
 * @param ciphertext_len_out Actual length of encrypted output
 * @return true if encryption successful, false otherwise
 */
bool crypto_aes_gcm_encrypt(
    const uint8_t* plaintext,
    uint16_t plaintext_len,
    const uint8_t* key,
    uint8_t* ciphertext_out,
    uint16_t* ciphertext_len_out
);

/**
 * @brief Decrypt a frame payload using AES-128-GCM
 * 
 * Decrypts the payload and verifies authentication tag.
 * Input format: [IV (12 bytes)][Ciphertext (len bytes)][Tag (16 bytes)]
 * 
 * @param ciphertext Input encrypted data (IV + ciphertext + tag)
 * @param ciphertext_len Length of entire encrypted input
 * @param key AES-128 key (16 bytes)
 * @param plaintext_out Output buffer (must be >= ciphertext_len - ENCRYPTION_OVERHEAD)
 * @param plaintext_len_out Actual length of decrypted output
 * @return true if decryption and authentication successful, false otherwise
 */
bool crypto_aes_gcm_decrypt(
    const uint8_t* ciphertext,
    uint16_t ciphertext_len,
    const uint8_t* key,
    uint8_t* plaintext_out,
    uint16_t* plaintext_len_out
);

/**
 * @brief Decrypt a frame if the protocol state requires it
 *
 * Checks current_state in protocol_state to determine if decryption is needed.
 * If state >= 0x22 (after channel verification), decrypts the frame.
 *
 * @param frame_buffer Buffer containing frame bytes (encrypted or plaintext)
 * @param frame_len Frame length
 * @param decrypted_frame_out Output buffer for decrypted frame
 * @param decrypted_len_out Length of decrypted frame
 * @return true if processing successful (decrypted or passthrough), false on error
 */
bool crypto_decrypt_frame_if_needed(
    uint8_t* frame_buffer,
    uint16_t frame_len,
    uint8_t* decrypted_frame_out,
    uint16_t* decrypted_len_out
);

/**
 * @brief Encrypt a frame if the protocol state requires it
 *
 * Checks current_state in protocol_state to determine if encryption is needed.
 * If state >= 0x22 (after channel verification), encrypts the frame.
 *
 * @param msg_type Message type (unused, kept for API compatibility)
 * @param frame Complete frame bytes
 * @param frame_len Frame length
 * @param encrypted_frame_out Output buffer for encrypted frame
 * @param encrypted_len_out Length of encrypted output
 * @return true if processing successful (encrypted or passthrough), false on error
 */
bool crypto_encrypt_frame_if_needed(
    uint8_t msg_type,
    const uint8_t* frame,
    uint16_t frame_len,
    uint8_t* encrypted_frame_out,
    uint16_t* encrypted_len_out
);

/**
 * @brief Derive session key from ECDH shared secret using HKDF-SHA256
 * 
 * @param shared_secret 32-byte shared secret from ECDH
 * @param session_key_out 16-byte AES-128 session key output
 * @return true if derivation successful, false otherwise
 */
bool crypto_derive_session_key(const uint8_t* shared_secret, uint8_t* session_key_out);

// ============================================================================
// ECDH Key Exchange Functions (using ATECC608A)
// ============================================================================

// ATECC608A slot assignments
#define SLOT_PERMANENT_PRIVKEY  0   // Permanent private key for signing
#define SLOT_HOST_PUBKEY        8   // Host's permanent public key (64 bytes)

// Key sizes
#define ECDH_PUBKEY_SIZE       64   // P-256 public key (X + Y coordinates)
#define ECDH_SIGNATURE_SIZE    64   // ECDSA signature (R + S components)
#define ECDH_SHARED_SECRET_SIZE 32  // ECDH shared secret output

/**
 * @brief Generate ephemeral keypair in ATECC608A TempKey
 * 
 * The private key is stored in volatile TempKey memory.
 * The public key is returned for transmission to peer.
 * 
 * @param ephemeral_pubkey_out Buffer to receive 64-byte public key
 * @return true on success, false on failure
 */
bool crypto_ecdh_generate_ephemeral_key(uint8_t* ephemeral_pubkey_out);

/**
 * @brief Sign a message using permanent private key in Slot 0
 * 
 * @param message Message to sign (typically hash of data)
 * @param message_len Length of message (typically 32 bytes for SHA256)
 * @param signature_out Buffer to receive 64-byte signature
 * @return true on success, false on failure
 */
bool crypto_ecdh_sign_with_permanent_key(const uint8_t* message, size_t message_len, 
                                   uint8_t* signature_out);

/**
 * @brief Read host's permanent public key from Slot 8
 * 
 * @param host_pubkey_out Buffer to receive 64-byte public key
 * @return true on success, false on failure
 */
bool crypto_ecdh_read_host_pubkey(uint8_t* host_pubkey_out);

/**
 * @brief Verify signature using host's permanent public key
 * 
 * @param message Message that was signed (typically hash)
 * @param message_len Length of message (typically 32 bytes)
 * @param signature Signature to verify (64 bytes)
 * @param host_pubkey Host's public key (64 bytes)
 * @return true if signature is valid, false otherwise
 */
bool crypto_ecdh_verify_signature(const uint8_t* message, size_t message_len,
                           const uint8_t* signature, const uint8_t* host_pubkey);

/**
 * @brief Perform ECDH using ephemeral key in TempKey
 * 
 * Uses the ephemeral private key stored in TempKey and the peer's
 * ephemeral public key to compute the shared secret.
 * 
 * @param peer_ephemeral_pubkey Peer's ephemeral public key (64 bytes)
 * @param shared_secret_out Buffer to receive 32-byte shared secret
 * @return true on success, false on failure
 */
bool crypto_ecdh_compute_shared_secret(const uint8_t* peer_ephemeral_pubkey,
                                uint8_t* shared_secret_out);

/**
 * @brief Read token's permanent public key from Slot 0
 * 
 * This is used by the host to verify the token's identity.
 * In production, this should be read once and hardcoded on the host.
 * 
 * @param token_pubkey_out Buffer to receive 64-byte public key
 * @return true on success, false on failure
 */
bool crypto_ecdh_read_token_pubkey(uint8_t* token_pubkey_out);

/**
 * @brief Verify integrity challenge response from host
 *
 * Verifies that the host's integrity response is correctly signed.
 * The message format is: hash (32 bytes) || nonce (4 bytes)
 *
 * @param hash 32-byte golden hash
 * @param nonce 4-byte nonce that was sent to the host
 * @param signature 64-byte ECDSA signature from host
 * @param host_pubkey 64-byte host permanent public key
 * @param result Output parameter: true if signature is valid, false otherwise
 * @return true if verification operation succeeded, false on error
 */
bool crypto_verify_integrity_challenge(const uint8_t* hash, uint32_t nonce,
                           const uint8_t* signature, const uint8_t* host_pubkey, bool *result);

// ============================================================================
// POC/Testing Functions - TEMPORARY
// ============================================================================

/**
 * @brief Get the hardcoded POC AES key for testing
 * 
 * TEMPORARY: For initial testing with hardcoded encryption
 * This will be removed once ECDH key exchange is working
 * 
 * @return Pointer to 16-byte hardcoded key
 */
const uint8_t* crypto_get_poc_aes_key(void);

/**
 * @brief Enable/disable forced encryption for testing
 * 
 * TEMPORARY: When enabled, all messages are encrypted regardless of state
 * 
 * @param enable true to force encryption, false to use state-based logic
 */
void crypto_set_force_encryption(bool enable);

/**
 * This function gets the golden hash from the ATECC and returns it.
 * @param p_result pointer to the receiving buffer (size 32 uint8_t array) of the golden hash.
 * @return true if successful, false otherwise.
 */
bool crypto_get_golden_hash(uint8_t* p_result);

/**
 * This function sets the golden hash to the ATECC's slot 8 (data zone, 416 bytes)
 * slot 8 layout (ours) <pubkey 64B>(data block 0+1)|<golden hash 32B> (data block 2)
 * @param p_hash pointer to the (size 32 uint8_t array) of the golden hash.
 * @return true if successful, false otherwise.
 */
bool crypto_set_golden_hash(uint8_t* p_hash);

#endif // CRYPT_H
