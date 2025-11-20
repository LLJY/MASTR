#include "crypto.h"
#include "protocol.h"
#include "serial.h"
#include "constants.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#ifndef UNIT_TEST
#include "FreeRTOS.h"
#include "task.h"
#include "pico/stdlib.h"
#include "pico/rand.h"
#ifdef LIB_PICO_SHA256
#include "pico/sha256.h"
#endif
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "cryptoauthlib.h"
#endif

bool crypto_init(void) {
#ifndef UNIT_TEST
    return true;
#else
    return true;
#endif
}

// ============================================================================
// Token permanent public key prefetch/cache
// ============================================================================
static char g_token_pubkey_hex[129];
static volatile bool g_token_pubkey_ready = false;
static volatile bool g_token_pubkey_failed = false;

// Prefetch task only for non-unit-test builds
#ifndef UNIT_TEST
static void token_pubkey_prefetch_task(void *arg) {
    (void)arg;
    for (int attempt = 0; attempt < 3 && !g_token_pubkey_ready; attempt++) {
        uint8_t raw[64];
        ATCA_STATUS status = atcab_get_pubkey(SLOT_PERMANENT_PRIVKEY, raw);
        if (status == ATCA_SUCCESS) {
            static const char HEX[] = "0123456789abcdef";
            for (int i = 0; i < 64; i++) {
                uint8_t b = raw[i];
                g_token_pubkey_hex[i*2]     = HEX[b >> 4];
                g_token_pubkey_hex[i*2 + 1] = HEX[b & 0x0F];
            }
            g_token_pubkey_hex[128] = '\0';
            g_token_pubkey_ready = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (!g_token_pubkey_ready) {
        g_token_pubkey_failed = true;
    }
    vTaskDelete(NULL);
}

void crypto_spawn_pubkey_prefetch(void) {
    if (!g_token_pubkey_ready && !g_token_pubkey_failed) {
        xTaskCreate(token_pubkey_prefetch_task, "pk_prefetch", 768, NULL, tskIDLE_PRIORITY + 1, NULL);
    }
}
#else
void crypto_spawn_pubkey_prefetch(void) {
    // Mark failed in unit test mode; hardware not available
    g_token_pubkey_failed = true;
}
#endif

bool crypto_get_cached_token_pubkey_hex(const char **hex_out, bool *ready_out) {
    if (hex_out) *hex_out = g_token_pubkey_hex;
    if (ready_out) *ready_out = g_token_pubkey_ready;
    return g_token_pubkey_ready;
}

bool crypto_token_pubkey_failed(void) { return g_token_pubkey_failed; }

/**
 * Generates initialization vector for AES-GCM using hardware RNG.
 * Uses Pico's hardware random number generator for cryptographically secure IVs.
 */
static void generate_iv(uint8_t* const iv_out) {
#ifndef UNIT_TEST
    // Use Pico hardware RNG for cryptographically secure random IV
    for (int i = 0; i < GCM_IV_SIZE; i++) {
        iv_out[i] = (uint8_t)get_rand_32();
    }
#else
    memset(iv_out, 0xAA, GCM_IV_SIZE);
#endif
}

/**
 * Computes SHA256 hash of message.
 * Uses hardware acceleration on RP2350, software on RP2040.
 *
 * Set FORCE_SOFTWARE_SHA256=1 to test software SHA256 on RP2350.
 *
 * @param message Input message to hash
 * @param message_len Length of input message
 * @param hash_out Output buffer for 32-byte hash
 */
static void compute_sha256(const uint8_t* message, size_t message_len, uint8_t* hash_out) {
#ifndef UNIT_TEST
#if defined(LIB_PICO_SHA256) && !defined(FORCE_SOFTWARE_SHA256)
    // RP2350: Use hardware SHA256 for maximum speed
    pico_sha256_state_t state;
    sha256_result_t result;
    pico_sha256_start_blocking(&state, SHA256_BIG_ENDIAN, false);
    pico_sha256_update_blocking(&state, message, message_len);
    pico_sha256_finish(&state, &result);
    memcpy(hash_out, result.bytes, 32);
#else
    // RP2040 or FORCE_SOFTWARE_SHA256: Use mbedtls software SHA256
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);  // 0 = SHA256 (not SHA224)
    mbedtls_sha256_update(&ctx, message, message_len);
    mbedtls_sha256_finish(&ctx, hash_out);
    mbedtls_sha256_free(&ctx);
#endif
#else
    (void)message; (void)message_len;
    memset(hash_out, 0, 32);
#endif
}

/**
 * Encrypts plaintext using AES-128-GCM.
 * Output format: [IV (12)][Ciphertext (N)][Tag (16)]
 *
 * @return true if encryption succeeded, false otherwise
 */
__attribute__((hot, nonnull(1, 3, 4, 5)))
bool crypto_aes_gcm_encrypt(
    const uint8_t* restrict plaintext,
    uint16_t plaintext_len,
    const uint8_t* restrict key,
    uint8_t* restrict ciphertext_out,
    uint16_t* restrict ciphertext_len_out
) {
#ifndef UNIT_TEST
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    // Generate random IV
    uint8_t iv[GCM_IV_SIZE];
    generate_iv(iv);

    // Set up the GCM context with AES-128
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    uint8_t tag[GCM_TAG_SIZE];

    ret = mbedtls_gcm_crypt_and_tag(
        &gcm,
        MBEDTLS_GCM_ENCRYPT,
        plaintext_len,
        iv, GCM_IV_SIZE,
        NULL, 0,
        plaintext,
        ciphertext_out + GCM_IV_SIZE,
        GCM_TAG_SIZE,
        tag
    );

    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        return false;
    }

    memcpy(ciphertext_out, iv, GCM_IV_SIZE);
    memcpy(ciphertext_out + GCM_IV_SIZE + plaintext_len, tag, GCM_TAG_SIZE);

    *ciphertext_len_out = GCM_IV_SIZE + plaintext_len + GCM_TAG_SIZE;

    return true;
#else
    (void)plaintext; (void)plaintext_len; (void)key;
    (void)ciphertext_out; (void)ciphertext_len_out;
    return false;
#endif
}

/**
 * Decrypts ciphertext using AES-128-GCM with authentication.
 * Input format: [IV (12)][Ciphertext (N)][Tag (16)]
 *
 * @return true if decryption and authentication succeeded, false otherwise
 */
__attribute__((hot, nonnull(1, 3, 4, 5)))
bool crypto_aes_gcm_decrypt(
    const uint8_t* restrict ciphertext,
    uint16_t ciphertext_len,
    const uint8_t* restrict key,
    uint8_t* restrict plaintext_out,
    uint16_t* restrict plaintext_len_out
) {
#ifndef UNIT_TEST
    if (ciphertext_len < ENCRYPTION_OVERHEAD) {
        return false;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    const uint8_t* iv = ciphertext;
    const uint8_t* encrypted_data = ciphertext + GCM_IV_SIZE;
    uint16_t encrypted_len = ciphertext_len - GCM_IV_SIZE - GCM_TAG_SIZE;
    const uint8_t* tag = ciphertext + ciphertext_len - GCM_TAG_SIZE;

    uint8_t temp_plaintext[256];

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    ret = mbedtls_gcm_auth_decrypt(
        &gcm,
        encrypted_len,
        iv, GCM_IV_SIZE,
        NULL, 0,
        tag, GCM_TAG_SIZE,
        encrypted_data,
        temp_plaintext
    );

    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        return false;
    }

    memcpy(plaintext_out, temp_plaintext, encrypted_len);
    *plaintext_len_out = encrypted_len;

    return true;
#else
    (void)ciphertext; (void)ciphertext_len; (void)key;
    (void)plaintext_out; (void)plaintext_len_out;
    return false;
#endif
}

/**
 * Decrypts frame if protocol state requires it (state >= 0x22).
 * For unencrypted states, passes frame through unchanged.
 *
 * @return true if processing succeeded, false on decryption failure
 */
__attribute__((nonnull(1, 3, 4)))
bool crypto_decrypt_frame_if_needed(
    uint8_t* restrict frame_buffer,
    uint16_t frame_len,
    uint8_t* restrict decrypted_frame_out,
    uint16_t* restrict decrypted_len_out
) {
    extern protocol_state_t g_protocol_state;

    // Use decoupled encryption flag instead of state
    const bool should_decrypt = g_protocol_state.is_encrypted;

    if (likely(should_decrypt)) {
        if (!crypto_aes_gcm_decrypt(frame_buffer, frame_len, g_protocol_state.aes_session_key,
                            decrypted_frame_out, decrypted_len_out)) {
            return false;
        }
    } else {
        memcpy(decrypted_frame_out, frame_buffer, frame_len);
        *decrypted_len_out = frame_len;
    }

    return true;
}

/**
 * Encrypts frame if protocol state requires it (state >= 0x22).
 * For unencrypted states, passes frame through unchanged.
 *
 * @return true if processing succeeded, false on encryption failure
 */
__attribute__((nonnull(2, 4, 5)))
bool crypto_encrypt_frame_if_needed(
    uint8_t msg_type,
    const uint8_t* restrict frame,
    uint16_t frame_len,
    uint8_t* restrict encrypted_frame_out,
    uint16_t* restrict encrypted_len_out
) {
    (void)msg_type;  // Unused in this implementation

    extern protocol_state_t g_protocol_state;

    // Use decoupled encryption flag instead of state
    const bool should_encrypt = g_protocol_state.is_encrypted;

    if (likely(should_encrypt)) {
        if (!crypto_aes_gcm_encrypt(frame, frame_len, g_protocol_state.aes_session_key,
                            encrypted_frame_out, encrypted_len_out)) {
            return false;
        }
    } else {
        memcpy(encrypted_frame_out, frame, frame_len);
        *encrypted_len_out = frame_len;
    }

    return true;
}

/**
 * Derives AES-128 session key from ECDH shared secret using HKDF-SHA256.
 * Uses salt "MASTR-Session-Key-v1" and empty info parameter.
 *
 * @param shared_secret 32-byte ECDH shared secret
 * @param session_key_out Output buffer for 16-byte AES key
 * @return true if derivation succeeded, false otherwise
 */
bool crypto_derive_session_key(const uint8_t* shared_secret, uint8_t* session_key_out) {
#ifndef UNIT_TEST

    const uint8_t salt[] = "MASTR-Session-Key-v1"; // Application-specific salt
    const uint8_t info[] = "";  // Optional context/info (empty for now)

    // Use mbedTLS HKDF
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        return false;
    }

    int ret = mbedtls_hkdf(
        md_info,
        salt, sizeof(salt) - 1,  // Salt (exclude null terminator)
        shared_secret, 32,        // Input key material (32-byte ECDH output)
        info, 0,                  // Info (empty)
        session_key_out, AES_KEY_SIZE  // Output key (16 bytes for AES-128)
    );

    if (ret != 0) {
        return false;
    }

    return true;
#else
    (void)shared_secret; (void)session_key_out;
    return false;
#endif
}

/**
 * Generates ephemeral P-256 keypair using ATECC608A.
 * Private key stored in volatile TempKey, public key returned.
 *
 * @param ephemeral_pubkey_out Output buffer for 64-byte public key (X||Y)
 * @return true if generation succeeded, false otherwise
 */
bool crypto_ecdh_generate_ephemeral_key(uint8_t* ephemeral_pubkey_out) {
#ifndef UNIT_TEST
    ATCA_STATUS status = atcab_genkey(ATCA_TEMPKEY_KEYID, ephemeral_pubkey_out);

    if (status != ATCA_SUCCESS) {
        return false;
    }

    return true;
#else
    (void)ephemeral_pubkey_out;
    return false;
#endif
}

/**
 * Signs message with token's permanent private key (ATECC608A Slot 0).
 * Returns raw signature format (R||S, 64 bytes), not DER.
 *
 * @param message Message to sign (will be hashed if not already 32 bytes)
 * @param message_len Length of message
 * @param signature_out Output buffer for 64-byte signature
 * @return true if signing succeeded, false otherwise
 */
bool crypto_ecdh_sign_with_permanent_key(const uint8_t* message, size_t message_len,
                                   uint8_t* signature_out) {
#ifndef UNIT_TEST
    uint8_t hash[32];
    if (message_len == 32) {
        memcpy(hash, message, 32);
    } else {
        compute_sha256(message, message_len, hash);
    }

    // Sign using permanent private key in Slot 0
    ATCA_STATUS status = atcab_sign(SLOT_PERMANENT_PRIVKEY, hash, signature_out);

    if (status != ATCA_SUCCESS) {
        return false;
    }

    return true;
#else
    (void)message; (void)message_len; (void)signature_out;
    return false;
#endif
}

/**
 * Reads host's permanent public key from ATECC608A Slot 8.
 * Reads 64 bytes in two 32-byte blocks (ATECC limitation).
 *
 * @param host_pubkey_out Output buffer for 64-byte public key
 * @return true if read succeeded, false otherwise
 */
bool crypto_ecdh_read_host_pubkey(uint8_t* host_pubkey_out) {
#ifndef UNIT_TEST
    for (int block = 0; block < 2; block++) {
        ATCA_STATUS status = atcab_read_zone(
            ATCA_ZONE_DATA,
            SLOT_HOST_PUBKEY,
            block,
            0,
            host_pubkey_out + (block * 32),
            32
        );

        if (status != ATCA_SUCCESS) {
            print_dbg("ATECC error code: 0x%02X", status);
            return false;
        }
    }

    return true;
#else
    (void)host_pubkey_out;
    return false;
#endif
}

/**
 * Stores 64-byte host permanent public key (X||Y) into ATECC608A Slot 8.
 * Performs two 32-byte block writes (block 0 and 1). Does not touch block 2
 * where the golden hash resides.
 */
bool crypto_set_host_pubkey(const uint8_t* host_pubkey) {
#ifndef UNIT_TEST
    if (!host_pubkey) return false;
    // Write two blocks of 32 bytes
    for (int block = 0; block < 2; block++) {
        ATCA_STATUS status = atcab_write_zone(
            ATCA_ZONE_DATA,
            SLOT_HOST_PUBKEY,   // slot 8
            block,              // block 0 or 1
            0,                  // offset
            host_pubkey + (block * 32),
            32
        );
        if (status != ATCA_SUCCESS) {
            return false;
        }
    }
    return true;
#else
    (void)host_pubkey; return false;
#endif
}

int crypto_hex_to_bytes(const char* hex_str, uint8_t* out_bytes, size_t max_bytes) {
    if (!hex_str || !out_bytes) return -1;

    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) return -1; // Must be even number of hex chars

    size_t byte_count = hex_len / 2;
    if (byte_count > max_bytes) return -1; // Not enough space in output buffer

    for (size_t i = 0; i < byte_count; i++) {
        char hex_pair[3] = {hex_str[i*2], hex_str[i*2+1], '\0'};
        unsigned int byte;
        if (sscanf(hex_pair, "%02x", &byte) != 1) {
            return -1; // Invalid hex character
        }
        out_bytes[i] = (uint8_t)byte;
    }

    return (int)byte_count;
}

bool crypto_set_host_pubkey_hex(const char* hex_pubkey) {
    if (!hex_pubkey) return false;

    // Expect exactly 128 hex characters (64 bytes)
    if (strlen(hex_pubkey) != 128) return false;

    uint8_t host_pubkey[64];
    int bytes_converted = crypto_hex_to_bytes(hex_pubkey, host_pubkey, sizeof(host_pubkey));
    if (bytes_converted != 64) return false;

    return crypto_set_host_pubkey(host_pubkey);
}

/**
 * Verifies ECDSA signature using ATECC608A hardware verification.
 * Uses host's permanent public key for verification.
 *
 * @param message Message that was signed (will be hashed if not already 32 bytes)
 * @param message_len Length of message
 * @param signature 64-byte signature in raw format (R||S)
 * @param host_pubkey 64-byte host public key
 * @return true if signature is valid, false otherwise
 */
bool crypto_ecdh_verify_signature(const uint8_t* message, size_t message_len,
                           const uint8_t* signature, const uint8_t* host_pubkey) {
#ifndef UNIT_TEST
    uint8_t hash[32];
    if (message_len == 32) {
        memcpy(hash, message, 32);
    } else {
        compute_sha256(message, message_len, hash);
    }

    bool is_verified = false;
    ATCA_STATUS status = atcab_verify_extern(hash, signature, host_pubkey, &is_verified);

    if (status != ATCA_SUCCESS) {
        return false;
    }

    if (!is_verified) {
        return false;
    }

    return true;
#else
    (void)message; (void)message_len; (void)signature; (void)host_pubkey;
    return false;
#endif
}

/**
 * Computes ECDH shared secret using ephemeral private key in TempKey.
 * Uses ATECC608A hardware to perform P-256 ECDH operation.
 *
 * @param peer_ephemeral_pubkey Peer's 64-byte ephemeral public key
 * */
bool crypto_ecdh_compute_shared_secret(const uint8_t* peer_ephemeral_pubkey,
                                uint8_t* shared_secret_out) {
#ifndef UNIT_TEST
    ATCA_STATUS status = atcab_ecdh_tempkey(
        peer_ephemeral_pubkey,
        shared_secret_out
    );

    if (status != ATCA_SUCCESS) {
        return false;
    }

    return true;
#else
    (void)peer_ephemeral_pubkey; (void)shared_secret_out;
    return false;
#endif
}

/**
 * Reads token's permanent public key from ATECC608A Slot 0.
 *
 * @param token_pubkey_out Output buffer for 64-byte public key
 * @return true if read succeeded, false otherwise
 */
bool crypto_ecdh_read_token_pubkey(uint8_t* token_pubkey_out) {
#ifndef UNIT_TEST
    ATCA_STATUS status = atcab_get_pubkey(SLOT_PERMANENT_PRIVKEY, token_pubkey_out);

    if (status != ATCA_SUCCESS) {
        return false;
    }

    return true;
#else
    (void)token_pubkey_out;
    return false;
#endif
}

/**
 * Verifies the integrity challenge response from the host.
 * The host signs (hash || nonce) with its permanent private key.
 * We reconstruct the message and verify the signature.
 *
 * @param p_hash 32-byte golden hash
 * @param nonce 4-byte nonce
 * @param p_signature 64-byte ECDSA signature
 * @param p_host_pubkey 64-byte host permanent public key
 * @param p_result Output: true if signature is valid, false otherwise
 * @return true if operation succeeded, false on error
 */
bool crypto_verify_integrity_challenge(const uint8_t* p_hash, uint32_t nonce,
                           const uint8_t* p_signature, const uint8_t* p_host_pubkey, bool *p_result){
#ifndef UNIT_TEST
    // Create buffer to concatenate hash (32 bytes) + nonce (4 bytes) = 36 bytes
    uint8_t message[36];

    // Copy hash to the beginning of the buffer
    memcpy(message, p_hash, 32);

    // Copy nonce bytes after the hash
    // The nonce is a uint32_t, so we copy its 4 bytes
    memcpy(message + 32, &nonce, 4);

    // The host signs SHA256(hash || nonce), so we need to hash the combined message
    uint8_t message_hash[32];
    compute_sha256(message, 36, message_hash);

    // Verify the signature using ATECC's external verification
    ATCA_STATUS status = atcab_verify_extern(message_hash, p_signature, p_host_pubkey, p_result);

    if (status != ATCA_SUCCESS) {
        print_dbg("ATECC error code: 0x%02X", status);
        return false;
    }

    return true;
#else
    (void)hash; (void)nonce; (void)signature; (void)host_pubkey; (void)result;
    return false;
#endif
}

/**
 * This function gets the golden hash from the ATECC and returns it.
 * @param p_result pointer to the receiving buffer (size 32 uint8_t array) of the golden hash.
 * @return true if successful, false otherwise.
 */
bool crypto_get_golden_hash(uint8_t* p_result){
    ATCA_STATUS atca_status = atcab_read_zone(
        ATCA_ZONE_DATA,
        8,
        2,
        0,
        p_result,
        32
    );

    if(atca_status != ATCA_SUCCESS){
        print_dbg("ATECC error code: 0x%02X", atca_status);
        return false;
    }
    return true;
}

/**
 * This function sets the golden hash to the ATECC's slot 8 (data zone, 416 bytes)
 * slot 8 layout (ours) <pubkey 64B>(data block 0+1)|<golden hash 32B> (data block 2)
 * @param p_hash pointer to the (size 32 uint8_t array) of the golden hash.
 * @return true if successful, false otherwise.
 */
bool crypto_set_golden_hash(uint8_t* p_hash){
    ATCA_STATUS atca_status = atcab_write_zone(
        ATCA_ZONE_DATA,     // Zone: data zone
        8,                  // Slot 8
        2,                  // Block number 2 (starts at byte 64)
        0,                  // Offset within block
        p_hash,            // 32-byte golden hash
        32                  // Write 32 bytes
    );

    if(atca_status != ATCA_SUCCESS){
        print_dbg("ATECC error code: 0x%02X", atca_status);
        return false;
    }
    return true;
}

/**
 * Checks if the token is provisioned.
 * Provisioned means the host's public key exists in the ATECC608A (Slot 8).
 *
 * @return true if host public key is stored and valid, false otherwise.
 */
bool crypto_is_token_provisioned(void) {
    uint8_t host_pubkey[64];
    return crypto_ecdh_read_host_pubkey(host_pubkey);
}

// ============================================================================
// Host pubkey non-blocking management system
// ============================================================================
static char g_host_pubkey_hex[129];
static volatile bool g_host_pubkey_read_ready = false;
static volatile bool g_host_pubkey_read_failed = false;
static volatile bool g_host_pubkey_write_pending = false;
static volatile bool g_host_pubkey_write_ready = false;
static volatile bool g_host_pubkey_write_failed = false;
static char g_pending_host_pubkey_hex[129];

// Golden hash operation state (non-blocking)
static uint8_t g_golden_hash_result[32];
static volatile bool g_golden_hash_write_pending = false;
static volatile bool g_golden_hash_write_ready = false;
static volatile bool g_golden_hash_write_failed = false;
static uint8_t g_pending_golden_hash[32];

#ifndef UNIT_TEST
// Background task for host pubkey operations
static void host_pubkey_task(void *arg) {
    (void)arg;

    // First, try to read existing host pubkey
    uint8_t host_pubkey[64];
    bool read_success = crypto_ecdh_read_host_pubkey(host_pubkey);

    if (read_success) {
        // Convert to hex
        static const char HEX[] = "0123456789abcdef";
        for (int i = 0; i < 64; i++) {
            uint8_t b = host_pubkey[i];
            g_host_pubkey_hex[i*2]     = HEX[b >> 4];
            g_host_pubkey_hex[i*2 + 1] = HEX[b & 0x0F];
        }
        g_host_pubkey_hex[128] = '\0';
        g_host_pubkey_read_ready = true;
    } else {
        g_host_pubkey_read_failed = true;
    }

    // Main loop for write operations
    while (1) {
        if (g_host_pubkey_write_pending) {
            g_host_pubkey_write_pending = false;
            g_host_pubkey_write_ready = false;
            g_host_pubkey_write_failed = false;

            // Convert hex to bytes
            uint8_t new_host_pubkey[64];
            int bytes_converted = crypto_hex_to_bytes(g_pending_host_pubkey_hex, new_host_pubkey, sizeof(new_host_pubkey));

            if (bytes_converted == 64) {
                // Attempt to write (blocking operation safe in background task)
                bool write_success = crypto_set_host_pubkey(new_host_pubkey);
                if (write_success) {
                    // Update cache with new value
                    strcpy(g_host_pubkey_hex, g_pending_host_pubkey_hex);
                    g_host_pubkey_read_ready = true;
                    g_host_pubkey_read_failed = false;
                    g_host_pubkey_write_ready = true;
                } else {
                    g_host_pubkey_write_failed = true;
                }
            } else {
                g_host_pubkey_write_failed = true;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void crypto_spawn_host_pubkey_task(void) {
    static bool task_spawned = false;
    if (!task_spawned) {
        xTaskCreate(host_pubkey_task, "hpk_task", 1024, NULL, tskIDLE_PRIORITY + 1, NULL);
        task_spawned = true;
    }
}
#else
void crypto_spawn_host_pubkey_task(void) {
    // No-op in unit test mode
}
#endif

// Non-blocking host pubkey API functions
bool crypto_get_cached_host_pubkey_hex(const char **hex_out, bool *ready_out, bool *failed_out) {
    if (hex_out) *hex_out = g_host_pubkey_hex;
    if (ready_out) *ready_out = g_host_pubkey_read_ready;
    if (failed_out) *failed_out = g_host_pubkey_read_failed;
    return g_host_pubkey_read_ready;
}

bool crypto_request_host_pubkey_write(const char *hex_pubkey, bool *write_ready_out, bool *write_failed_out) {
    if (!hex_pubkey || strlen(hex_pubkey) != 128) {
        return false;
    }

    if (g_host_pubkey_write_pending) {
        // Write already in progress
        if (write_ready_out) *write_ready_out = false;
        if (write_failed_out) *write_failed_out = false;
        return false;
    }

    // Copy hex string and start write operation
    strcpy(g_pending_host_pubkey_hex, hex_pubkey);
    g_host_pubkey_write_pending = true;
    g_host_pubkey_write_ready = false;
    g_host_pubkey_write_failed = false;

    if (write_ready_out) *write_ready_out = g_host_pubkey_write_ready;
    if (write_failed_out) *write_failed_out = g_host_pubkey_write_failed;
    return true;
}

bool crypto_get_host_pubkey_write_status(bool *write_ready_out, bool *write_failed_out) {
    if (write_ready_out) *write_ready_out = g_host_pubkey_write_ready;
    if (write_failed_out) *write_failed_out = g_host_pubkey_write_failed;
    return g_host_pubkey_write_ready;
}

#ifndef UNIT_TEST
// Background task for golden hash operations (non-blocking)
static void golden_hash_task(void *arg) {
    (void)arg;

    while (1) {
        if (g_golden_hash_write_pending) {
            g_golden_hash_write_pending = false;
            g_golden_hash_write_ready = false;
            g_golden_hash_write_failed = false;

            // Set golden hash (blocking operation safe in background task)
            bool write_success = crypto_set_golden_hash(g_pending_golden_hash);
            if (write_success) {
                // Verify by reading back
                uint8_t verify_hash[32];
                bool read_success = crypto_get_golden_hash(verify_hash);
                if (read_success && memcmp(g_pending_golden_hash, verify_hash, 32) == 0) {
                    // Success - store result
                    memcpy(g_golden_hash_result, verify_hash, 32);
                    g_golden_hash_write_ready = true;
                } else {
                    g_golden_hash_write_failed = true;
                }
            } else {
                g_golden_hash_write_failed = true;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void crypto_spawn_golden_hash_task(void) {
    static bool task_spawned = false;
    if (!task_spawned) {
        xTaskCreate(golden_hash_task, "gh_task", 1024, NULL, tskIDLE_PRIORITY + 1, NULL);
        task_spawned = true;
    }
}
#else
void crypto_spawn_golden_hash_task(void) {
    // No-op in unit test mode
}
#endif

// Non-blocking golden hash API functions
bool crypto_spawn_golden_hash_task_with_data(const uint8_t* golden_hash) {
    if (!golden_hash) {
        return false;
    }

    if (g_golden_hash_write_pending) {
        return false;  // Already busy
    }

    // Copy golden hash data and start write operation
    memcpy(g_pending_golden_hash, golden_hash, 32);
    g_golden_hash_write_pending = true;
    g_golden_hash_write_ready = false;
    g_golden_hash_write_failed = false;

    return true;
}

bool crypto_get_golden_hash_write_status(bool *write_ready_out, bool *write_failed_out, uint8_t *golden_hash_out) {
    if (write_ready_out) *write_ready_out = g_golden_hash_write_ready;
    if (write_failed_out) *write_failed_out = g_golden_hash_write_failed;
    if (golden_hash_out && g_golden_hash_write_ready) {
        memcpy(golden_hash_out, g_golden_hash_result, 32);
    }
    return g_golden_hash_write_ready;
}
