#include "crypt.h"
#include "protocol.h"
#include "serial.h"
#include <string.h>

#ifndef UNIT_TEST
#include "pico/stdlib.h"
#include "pico/rand.h"
#include "pico/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "cryptoauthlib.h"
#endif

bool crypt_init(void) {
#ifndef UNIT_TEST
    return true;
#else
    return true;
#endif
}

/**
 * Generates initialization vector for AES-GCM using hardware RNG.
 * Uses Pico's hardware random number generator for cryptographically secure IVs.
 */
static void generate_iv(uint8_t* iv_out) {
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
 * Encrypts plaintext using AES-128-GCM.
 * Output format: [IV (12)][Ciphertext (N)][Tag (16)]
 * 
 * @return true if encryption succeeded, false otherwise
 */bool aes_gcm_encrypt(
    const uint8_t* plaintext,
    uint16_t plaintext_len,
    const uint8_t* key,
    uint8_t* ciphertext_out,
    uint16_t* ciphertext_len_out
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
        // Cannot use print_dbg() - causes infinite recursion!
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
bool aes_gcm_decrypt(
    const uint8_t* ciphertext,
    uint16_t ciphertext_len,
    const uint8_t* key,
    uint8_t* plaintext_out,
    uint16_t* plaintext_len_out
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
 * Decrypts frame payload if protocol state requires it (state >= 0x22).
 * For unencrypted states, passes payload through unchanged.
 * 
 * @return true if processing succeeded, false on decryption failure
 */
bool decrypt_frame_if_needed(
    uint8_t* frame_buffer,
    uint16_t frame_len,
    uint8_t* decrypted_payload_out,
    uint16_t* decrypted_len_out
) {
    if (frame_len < 4) {
        return false; // Invalid frame
    }
    
    message_type_t msg_type = frame_buffer[0];
    uint16_t payload_len = ((uint16_t)frame_buffer[1] << 8) | frame_buffer[2];
    uint8_t* payload = &frame_buffer[3];
    
    extern protocol_state_t protocol_state;
    
    bool should_decrypt = (protocol_state.current_state >= 0x22);
    
    if (should_decrypt) {
        if (!aes_gcm_decrypt(payload, payload_len, protocol_state.aes_session_key,
                            decrypted_payload_out, decrypted_len_out)) {
            memcpy(decrypted_payload_out, payload, payload_len);
            *decrypted_len_out = payload_len;
            return false;
        }
    } else {
        memcpy(decrypted_payload_out, payload, payload_len);
        *decrypted_len_out = payload_len;
    }
    
    return true;
}

/**
 * Encrypts frame payload if protocol state requires it (state >= 0x22).
 * For unencrypted states, passes payload through unchanged.
 * 
 * @return true if processing succeeded, false on encryption failure
 */
bool encrypt_frame_if_needed(
    uint8_t msg_type,
    const uint8_t* payload,
    uint16_t payload_len,
    uint8_t* encrypted_payload_out,
    uint16_t* encrypted_len_out
) {
    extern protocol_state_t protocol_state;
    
    bool should_encrypt = (protocol_state.current_state >= 0x22);
    
    if (should_encrypt) {
        if (!aes_gcm_encrypt(payload, payload_len, protocol_state.aes_session_key,
                            encrypted_payload_out, encrypted_len_out)) {
            return false;
        }
    } else {
        memcpy(encrypted_payload_out, payload, payload_len);
        *encrypted_len_out = payload_len;
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
bool derive_session_key(const uint8_t* shared_secret, uint8_t* session_key_out) {
#ifndef UNIT_TEST
    
    const uint8_t salt[] = "MASTR-Session-Key-v1"; // Application-specific salt
    const uint8_t info[] = "";  // Optional context/info (empty for now)
    
    // Use mbedTLS HKDF
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        // Cannot use print_dbg() - causes infinite recursion!
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
bool ecdh_generate_ephemeral_key(uint8_t* ephemeral_pubkey_out) {
#ifndef UNIT_TEST
    ATCA_STATUS status = atcab_genkey(ATCA_TEMPKEY_KEYID, ephemeral_pubkey_out);
    
    if (status != ATCA_SUCCESS) {
        print_dbg("ECDH ERROR: Failed to generate ephemeral key: 0x%02X\n", status);
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
bool ecdh_sign_with_permanent_key(const uint8_t* message, size_t message_len,
                                   uint8_t* signature_out) {
#ifndef UNIT_TEST
    uint8_t hash[32];
    if (message_len == 32) {
        memcpy(hash, message, 32);
    } else {
        pico_sha256_state_t state;
        sha256_result_t result;
        pico_sha256_start_blocking(&state, SHA256_BIG_ENDIAN, false);
        pico_sha256_update_blocking(&state, message, message_len);
        pico_sha256_finish(&state, &result);
        memcpy(hash, result.bytes, 32);
    }
    
    // Sign using permanent private key in Slot 0
    ATCA_STATUS status = atcab_sign(SLOT_PERMANENT_PRIVKEY, hash, signature_out);
    
    if (status != ATCA_SUCCESS) {
        print_dbg("ECDH ERROR: Failed to sign message: 0x%02X\n", status);
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
bool ecdh_read_host_pubkey(uint8_t* host_pubkey_out) {
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
            print_dbg("ECDH ERROR: Failed to read host pubkey block %d: 0x%02X\n", block, status);
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
 * Verifies ECDSA signature using ATECC608A hardware verification.
 * Uses host's permanent public key for verification.
 * 
 * @param message Message that was signed (will be hashed if not already 32 bytes)
 * @param message_len Length of message
 * @param signature 64-byte signature in raw format (R||S)
 * @param host_pubkey 64-byte host public key
 * @return true if signature is valid, false otherwise
 */
bool ecdh_verify_signature(const uint8_t* message, size_t message_len,
                           const uint8_t* signature, const uint8_t* host_pubkey) {
#ifndef UNIT_TEST
    uint8_t hash[32];
    if (message_len == 32) {
        memcpy(hash, message, 32);
    } else {
        pico_sha256_state_t state;
        sha256_result_t result;
        pico_sha256_start_blocking(&state, SHA256_BIG_ENDIAN, false);
        pico_sha256_update_blocking(&state, message, message_len);
        pico_sha256_finish(&state, &result);
        memcpy(hash, result.bytes, 32);
    }
    
    bool is_verified = false;
    ATCA_STATUS status = atcab_verify_extern(hash, signature, host_pubkey, &is_verified);
    
    if (status != ATCA_SUCCESS) {
        print_dbg("ECDH ERROR: verify failed, status: 0x%02X\n", status);
        return false;
    }
    
    if (!is_verified) {
        print_dbg("ECDH ERROR: Signature invalid\n");
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
bool ecdh_compute_shared_secret(const uint8_t* peer_ephemeral_pubkey,
                                uint8_t* shared_secret_out) {
#ifndef UNIT_TEST
    ATCA_STATUS status = atcab_ecdh_tempkey(
        peer_ephemeral_pubkey,
        shared_secret_out
    );
    
    if (status != ATCA_SUCCESS) {
        print_dbg("ECDH ERROR: Failed to compute shared secret: 0x%02X\n", status);
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
bool ecdh_read_token_pubkey(uint8_t* token_pubkey_out) {
#ifndef UNIT_TEST
    ATCA_STATUS status = atcab_get_pubkey(SLOT_PERMANENT_PRIVKEY, token_pubkey_out);
    
    if (status != ATCA_SUCCESS) {
        print_dbg("ECDH ERROR: Failed to read token pubkey: 0x%02X\n", status);
        return false;
    }
    
    print_dbg("ECDH: Read token permanent pubkey from Slot 0\n");
    return true;
#else
    (void)token_pubkey_out;
    return false;
#endif
}
