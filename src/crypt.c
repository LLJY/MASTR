#include "crypt.h"
#include "protocol.h"
#include "serial.h"
#include <string.h>

#ifndef UNIT_TEST
#include "pico/stdlib.h"
#include "pico/rand.h"  // For get_rand_32()

// Use mbedTLS for AES-GCM on both RP2040 and RP2350
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

#endif // UNIT_TEST

// ============================================================================
// POC Hardcoded Key - TEMPORARY FOR TESTING
// ============================================================================

// This hardcoded key will be used for initial testing
// Once ECDH is working, this will be removed
static const uint8_t poc_aes_key[AES_KEY_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// TEMPORARY: Force encryption flag for testing
static bool force_encryption_enabled = false;

const uint8_t* get_poc_aes_key(void) {
    return poc_aes_key;
}

void set_force_encryption(bool enable) {
    force_encryption_enabled = enable;
}

// ============================================================================
// Crypto Initialization
// ============================================================================

bool crypt_init(void) {
#ifndef UNIT_TEST
    // NOTE: Cannot use print_dbg() here - would cause infinite recursion!
    // mbedTLS doesn't require explicit initialization for basic usage
    // The library is ready to use
    return true;
#else
    return true; // Mock for unit tests
#endif
}

// ============================================================================
// Random IV Generation
// ============================================================================

static void generate_iv(uint8_t* iv_out) {
#ifndef UNIT_TEST
    // Use hardware RNG from Pico SDK
    for (int i = 0; i < GCM_IV_SIZE; i += 4) {
        uint32_t random = get_rand_32();
        memcpy(iv_out + i, &random, (i + 4 <= GCM_IV_SIZE) ? 4 : (GCM_IV_SIZE - i));
    }
#else
    // Mock for unit tests
    memset(iv_out, 0xAA, GCM_IV_SIZE);
#endif
}

// ============================================================================
// AES-GCM Encryption/Decryption using mbedTLS
// ============================================================================

bool aes_gcm_encrypt(
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
    
    // Output format: [IV][Ciphertext][Tag]
    uint8_t tag[GCM_TAG_SIZE];
    
    // Perform authenticated encryption
    ret = mbedtls_gcm_crypt_and_tag(
        &gcm,
        MBEDTLS_GCM_ENCRYPT,
        plaintext_len,
        iv, GCM_IV_SIZE,
        NULL, 0,  // No additional authenticated data (AAD)
        plaintext,
        ciphertext_out + GCM_IV_SIZE,  // Ciphertext goes after IV
        GCM_TAG_SIZE,
        tag
    );
    
    mbedtls_gcm_free(&gcm);
    
    if (ret != 0) {
        // Cannot use print_dbg() - causes infinite recursion!
        return false;
    }
    
    // Copy IV to beginning of output
    memcpy(ciphertext_out, iv, GCM_IV_SIZE);
    
    // Copy tag to end of output
    memcpy(ciphertext_out + GCM_IV_SIZE + plaintext_len, tag, GCM_TAG_SIZE);
    
    *ciphertext_len_out = GCM_IV_SIZE + plaintext_len + GCM_TAG_SIZE;
    
    // Cannot use print_dbg() here - would cause infinite recursion!
    
    return true;
#else
    (void)plaintext; (void)plaintext_len; (void)key;
    (void)ciphertext_out; (void)ciphertext_len_out;
    return false;
#endif
}

bool aes_gcm_decrypt(
    const uint8_t* ciphertext,
    uint16_t ciphertext_len,
    const uint8_t* key,
    uint8_t* plaintext_out,
    uint16_t* plaintext_len_out
) {
#ifndef UNIT_TEST
    // Verify minimum length
    if (ciphertext_len < ENCRYPTION_OVERHEAD) {
        // Cannot use print_dbg() - causes infinite recursion!
        return false;
    }
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    // Extract IV, ciphertext, and tag
    const uint8_t* iv = ciphertext;
    const uint8_t* encrypted_data = ciphertext + GCM_IV_SIZE;
    uint16_t encrypted_len = ciphertext_len - GCM_IV_SIZE - GCM_TAG_SIZE;
    const uint8_t* tag = ciphertext + ciphertext_len - GCM_TAG_SIZE;
    
    // Set up the GCM context with AES-128
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8);
    if (ret != 0) {
        // Cannot use print_dbg() - causes infinite recursion!
        mbedtls_gcm_free(&gcm);
        return false;
    }
    
    // Perform authenticated decryption
    ret = mbedtls_gcm_auth_decrypt(
        &gcm,
        encrypted_len,
        iv, GCM_IV_SIZE,
        NULL, 0,  // No additional authenticated data (AAD)
        tag, GCM_TAG_SIZE,
        encrypted_data,
        plaintext_out
    );
    
    mbedtls_gcm_free(&gcm);
    
    if (ret != 0) {
        // Cannot use print_dbg() - causes infinite recursion!
        return false;
    }
    
    *plaintext_len_out = encrypted_len;
    
    // Cannot use print_dbg() here - would cause infinite recursion!
    
    return true;
#else
    (void)ciphertext; (void)ciphertext_len; (void)key;
    (void)plaintext_out; (void)plaintext_len_out;
    return false;
#endif
}

// ============================================================================
// Protocol Integration Functions
// ============================================================================

bool decrypt_frame_if_needed(
    uint8_t* frame_buffer,
    uint16_t frame_len,
    uint8_t* decrypted_payload_out,
    uint16_t* decrypted_len_out
) {
    // Frame format: [Type(1)][Length_H(1)][Length_L(1)][Payload...][Checksum(1)]
    
    if (frame_len < 4) {
        return false; // Invalid frame
    }
    
    message_type_t msg_type = frame_buffer[0];
    uint16_t payload_len = ((uint16_t)frame_buffer[1] << 8) | frame_buffer[2];
    uint8_t* payload = &frame_buffer[3];
    
    // Access the global protocol state (extern declared in protocol.h)
    extern protocol_state_t protocol_state;
    
    // Determine if we should decrypt based on state
    // State >= 0x22: All messages after channel verification are encrypted
    // Force encryption flag is for POC testing only
    bool should_decrypt = false;
    
    if (force_encryption_enabled) {
        // TEMPORARY POC: Always decrypt when force mode is enabled
        should_decrypt = true;
    } else {
        // Normal operation: decrypt if we're past channel verification (state >= 0x22)
        // State 0x20-0x21: ECDH exchange (unencrypted)
        // State >= 0x22: Channel verified, all messages encrypted
        if (protocol_state.current_state >= 0x22) {
            should_decrypt = true;
        }
    }
    
    if (should_decrypt) {
        // Decrypt the payload using session key
        // (In POC mode, this is set to poc_aes_key during init)
        // (In normal mode, this is derived from ECDH)
        if (!aes_gcm_decrypt(payload, payload_len, protocol_state.aes_session_key,
                            decrypted_payload_out, decrypted_len_out)) {
            // Cannot use print_dbg() - causes infinite recursion!
            return false;
        }
        
        // Cannot use print_dbg() here - would cause infinite recursion!
    } else {
        // Passthrough - no decryption needed
        memcpy(decrypted_payload_out, payload, payload_len);
        *decrypted_len_out = payload_len;
    }
    
    return true;
}

bool encrypt_frame_if_needed(
    uint8_t msg_type,
    const uint8_t* payload,
    uint16_t payload_len,
    uint8_t* encrypted_payload_out,
    uint16_t* encrypted_len_out
) {
    // Access the global protocol state
    extern protocol_state_t protocol_state;
    
    // Determine if we should encrypt based on state
    // State >= 0x22: All messages after channel verification are encrypted
    // Force encryption flag is for POC testing only
    bool should_encrypt = false;
    
    if (force_encryption_enabled) {
        // TEMPORARY POC: Always encrypt when force mode is enabled
        should_encrypt = true;
    } else {
        // Normal operation: encrypt if we're past channel verification (state >= 0x22)
        // State 0x20-0x21: ECDH exchange (unencrypted)
        // State >= 0x22: Channel verified, all messages encrypted
        if (protocol_state.current_state >= 0x22) {
            should_encrypt = true;
        }
    }
    
    if (should_encrypt) {
        // Use the session key (in POC mode, this is set to poc_aes_key during init)
        // (In normal mode, this is derived from ECDH)
        if (!aes_gcm_encrypt(payload, payload_len, protocol_state.aes_session_key,
                            encrypted_payload_out, encrypted_len_out)) {
            // Cannot use print_dbg() - causes infinite recursion!
            return false;
        }
        
        // Cannot use print_dbg() here - would cause infinite recursion!
    } else {
        // Passthrough - no encryption needed
        memcpy(encrypted_payload_out, payload, payload_len);
        *encrypted_len_out = payload_len;
    }
    
    return true;
}

// ============================================================================
// HKDF-SHA256 Key Derivation using mbedTLS
// ============================================================================

bool derive_session_key(const uint8_t* shared_secret, uint8_t* session_key_out) {
#ifndef UNIT_TEST
    // HKDF-SHA256 to derive 16-byte AES key from 32-byte ECDH shared secret
    
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
        // Cannot use print_dbg() - causes infinite recursion!
        return false;
    }
    
    // Cannot use print_dbg() here - would cause infinite recursion!
    
    return true;
#else
    (void)shared_secret; (void)session_key_out;
    return false;
#endif
}
