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
 * @brief Store host's permanent public key into ATECC608A Slot 8
 *
 * Writes the 64-byte P-256 public key (X||Y) into slot 8 using two
 * 32-byte block writes (block 0 and block 1). This centralizes the
 * storage logic so both the serial protocol path and HTTP API path
 * can call the same function.
 *
 * Layout note (slot 8):
 *   - Block 0..1: host public key (64 bytes)
 *   - Block 2:    golden hash (32 bytes)
 *
 * @param host_pubkey Pointer to 64-byte buffer containing X||Y
 * @return true on success, false otherwise
 */
bool crypto_set_host_pubkey(const uint8_t* host_pubkey);

// Token permanent public key prefetch/cache API
// Spawn background task (idempotent) to prefetch token permanent public key
void crypto_spawn_pubkey_prefetch(void);
// Retrieve cached hex (128 chars + NUL). Returns true if ready; sets *ready_out if provided.
bool crypto_get_cached_token_pubkey_hex(const char **hex_out, bool *ready_out);
// Returns true if prefetch permanently failed
bool crypto_token_pubkey_failed(void);

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

/**
 * Convert hex string to bytes
 * @param hex_str Null-terminated hex string (e.g., "deadbeef")
 * @param out_bytes Output buffer for bytes
 * @param max_bytes Maximum number of bytes to write to out_bytes
 * @return Number of bytes converted, or -1 on error
 */
int crypto_hex_to_bytes(const char* hex_str, uint8_t* out_bytes, size_t max_bytes);

/**
 * Set host public key from hex string
 * @param hex_pubkey 128-character hex string representing 64 bytes
 * @return true if successful, false otherwise
 */
bool crypto_set_host_pubkey_hex(const char* hex_pubkey);

// ============================================================================
// Non-blocking host pubkey management API
// ============================================================================

/**
 * Spawns the background task for host pubkey operations.
 * Call once during system initialization.
 */
void crypto_spawn_host_pubkey_task(void);

/**
 * Gets the cached host public key in hex format (non-blocking).
 * 
 * @param hex_out Pointer to receive hex string (128 chars + null terminator)
 * @param ready_out Pointer to receive ready status (true if pubkey is cached)
 * @param failed_out Pointer to receive failure status (true if read failed)
 * @return true if pubkey is ready and cached, false otherwise
 */
bool crypto_get_cached_host_pubkey_hex(const char **hex_out, bool *ready_out, bool *failed_out);

/**
 * Requests a host public key write operation (non-blocking).
 * The actual write happens in background task.
 * 
 * @param hex_pubkey 128-character hex string to write
 * @param write_ready_out Pointer to receive write completion status (optional)
 * @param write_failed_out Pointer to receive write failure status (optional)
 * @return true if write request was accepted, false if invalid or already pending
 */
bool crypto_request_host_pubkey_write(const char *hex_pubkey, bool *write_ready_out, bool *write_failed_out);

/**
 * Gets the status of the last host pubkey write operation (non-blocking).
 * 
 * @param write_ready_out Pointer to receive write completion status
 * @param write_failed_out Pointer to receive write failure status
 * @return true if write completed successfully, false otherwise
 */
bool crypto_get_host_pubkey_write_status(bool *write_ready_out, bool *write_failed_out);

/**
 * Spawn the golden hash background task (one-time initialization)
 * Safe to call multiple times - only creates task on first call
 */
void crypto_spawn_golden_hash_task(void);

/**
 * Queue a golden hash write operation (non-blocking)
 * @param golden_hash 32-byte golden hash to write
 * @return true if operation queued, false if busy
 */
bool crypto_spawn_golden_hash_task_with_data(const uint8_t* golden_hash);

/**
 * Get golden hash write operation status (non-blocking)
 * @param write_ready_out Pointer to receive write completion status
 * @param write_failed_out Pointer to receive write failure status  
 * @param golden_hash_out Pointer to receive verified golden hash (32 bytes, if ready)
 * @return true if write completed successfully, false otherwise
 */
bool crypto_get_golden_hash_write_status(bool *write_ready_out, bool *write_failed_out, uint8_t *golden_hash_out);

bool crypto_set_host_pubkey(const uint8_t* host_pubkey);

#endif // CRYPT_H
