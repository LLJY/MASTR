#include "protocol.h"
#include "projdefs.h"
#include "serial.h"
#include "crypto.h"
#include "constants.h"

#include <stdint.h>
#include <string.h>

#ifndef UNIT_TEST
#include "pico/rand.h"
#include "hal/hal_pico_i2c.h"
#include "cryptoauthlib.h"
#else
// Mock declarations for unit tests
#include "mock_time.h"
#endif

// Global protocol state
protocol_state_t g_protocol_state = {0};

// store golden hash and public key
void protocol_provision(const uint8_t* p_golden_hash,
    const uint8_t* p_pub_key,
    const uint8_t golden_hash_len,
    const uint8_t pub_key_len)
{
    #ifndef UNIT_TEST

    // sanity check the lengths
    if(golden_hash_len != 32 || pub_key_len != 64)
        return;

    crypto_set_golden_hash(p_golden_hash);
    crypto_set_host_pubkey(p_pub_key);

    #endif
}

// delete golden hash and public key
void protocol_unprovision(void){
    static const uint8_t zero_golden_hash[32] = {0};
    static const uint8_t zero_pub_key[64] = {0};

    protocol_provision(zero_golden_hash, zero_pub_key, sizeof(zero_golden_hash), sizeof(zero_pub_key));
    return;
}

// check if the protocol is provisioned, if not perform some function...
bool protocol_check_provisioned(void) {

    // Force 4-byte alignment
    static uint8_t host_pubkey[64] __attribute__((aligned(4)));

    if (crypto_ecdh_read_host_pubkey(host_pubkey) != true){
        return false;
    }

    // Force 4-byte alignment
    static uint8_t golden_hash[32] __attribute__((aligned(4)));
    if (crypto_get_golden_hash(golden_hash) != true){
        return false;

    }

    static const uint8_t zeros[64] __attribute__((aligned(4))) = {0};

    if (memcmp(host_pubkey, zeros, sizeof(host_pubkey)) == 0 ||
        memcmp(golden_hash, zeros, sizeof(golden_hash)) == 0)
        return false;

    return true; // Provisioned
}
// ============================================================================
// Session Management Functions
// ============================================================================

/**
 * Invalidate current session but KEEP old session key.
 * The old key is retained until a new one is successfully derived.
 * This allows encrypted communication during re-attestation.
 * Keeps encryption enabled (is_encrypted flag stays true).
 * Resets state to 0x20 to await new ECDH handshake.
 */
void protocol_invalidate_session(void) {
    g_protocol_state.session_valid = false;

    // DO NOT clear session key yet - keep old key for encrypted communication
    // The key will be overwritten when new ECDH completes successfully

    // Reset to initial ECDH state but keep encryption flag
    // This allows us to stay encrypted during re-attestation with old key
    g_protocol_state.current_state = 0x20;

    print_dbg("Session invalidated - awaiting re-attestation (keeping old key)\n");
}

/**
 * Trigger re-attestation cycle.
 * Token initiates by generating new ephemeral key and sending T2H_ECDH_SHARE.
 * This signals to the host that re-attestation is needed.
 */
void protocol_trigger_reattestation(void) {
    print_dbg("Triggering re-attestation cycle\n");

    // First invalidate session (keeps old key for encrypted communication)
    protocol_invalidate_session();

    // Generate new ephemeral keypair
    if (!crypto_ecdh_generate_ephemeral_key(g_protocol_state.et_pubkey)) {
        print_dbg("ERROR: Failed to generate ephemeral key for re-attestation\n");
        return;
    }

    #ifndef UNIT_TEST
    // Sign new ephemeral pubkey
    uint8_t token_signature[64];
    if (!crypto_ecdh_sign_with_permanent_key(g_protocol_state.et_pubkey, 64, token_signature)) {
        print_dbg("ERROR: Failed to sign ephemeral pubkey for re-attestation\n");
        return;
    }

    // Send T2H_ECDH_SHARE to signal re-attestation
    uint8_t response[128];
    memcpy(response, g_protocol_state.et_pubkey, 64);
    memcpy(response + 64, token_signature, 64);
    send_message(T2H_ECDH_SHARE, response, 128);

    print_dbg("Sent T2H_ECDH_SHARE for re-attestation (new ephemeral key)\n");
    #endif

    // Wait at state 0x21 for host's H2T_ECDH_SHARE
    g_protocol_state.current_state = 0x21;
}

/**
 * Check if current session is valid and not timed out.
 *
 * @return true if session is valid and within timeout, false otherwise
 */
bool protocol_is_session_valid(void) {
    if (!g_protocol_state.session_valid) {
        return false;
    }

    uint64_t current_time = time_us_64();
    uint64_t elapsed_ms = (current_time - g_protocol_state.session_start_timestamp) / 1000;

    return elapsed_ms < g_protocol_state.session_timeout_ms;
}
/**
 * An idiomatic panic helper that tells us what happens.
 * NOTE: WHEN IFDEBUG = 0 print_dbg WILL NOT OUTPUT ANYTHING.
 */
__attribute__((cold, noreturn, noinline))
void protocol_panic(const char* const reason){
    print_dbg("SOMETHING WENT WRONG PANIC %s", reason);
    protocol_enter_halt_spam_state();
    __builtin_unreachable();
}

/**
 * Enter permanent halt state and spam T2H_INTEGRITY_FAIL_HALT indefinitely.
 * This function never returns - it's a security measure for integrity failures.
 */
 #ifndef UNIT_TEST
 __attribute__((noreturn, cold, noinline))
 #endif
void protocol_enter_halt_spam_state(void) {
    g_protocol_state.in_halt_state = true;
    g_protocol_state.current_state = 0xFF;  // Permanent halt state

    print_dbg("=== ENTERING PERMANENT HALT STATE ===\n");
    print_dbg("INTEGRITY FAILURE DETECTED - NO RECOVERY\n");

    #ifndef UNIT_TEST
    // Spam T2H_INTEGRITY_FAIL_HALT indefinitely
    while (true) {
        send_message(T2H_INTEGRITY_FAIL_HALT, NULL, 0);
        vTaskDelay(pdMS_TO_TICKS(1000));  // Spam every second
    }
    __builtin_unreachable();
    #endif
}


// to be run in main
// pull all the data from the ATECC to fill the protocol_state_t protocol_state struct.
void set_protocol_initial_state(){
    g_protocol_state.protocol_begin_timestamp = time_us_64();
}

#ifdef UNIT_TEST
// Test hook to notify tests that handler was called
extern void test_hook_handle_validated_message_called(message_type_t msg_type, uint8_t* payload, uint16_t len);
#endif

/**
 * Handles incoming protocol messages after frame validation and decryption.
 * Enforces state machine progression and rejects out-of-order requests.
 *
 * @param msg_type Message type from protocol enum
 * @param payload Decrypted message payload
 * @param len Payload length in bytes
 */
void protocol_handle_validated_message(message_type_t msg_type, uint8_t* payload, uint16_t len)
{
    #ifdef UNIT_TEST
    // Notify tests that handler was called
    test_hook_handle_validated_message_called(msg_type, payload, len);
    #endif

    #ifdef DEBUG
    print_dbg("Received message type: 0x%02X, length: %d\n", msg_type, len);
    #endif

    switch (msg_type)
    {
        case H2T_ECDH_SHARE:
            // Accept ECDH at state 0x20 (initial) or 0x21 (re-attestation response)
            if (unlikely(g_protocol_state.current_state != 0x20 && g_protocol_state.current_state != 0x21)) {
                print_dbg("ERROR: ECDH share rejected (wrong state: 0x%02X)\n", g_protocol_state.current_state);
                send_shutdown_signal();
                break;
            }
            {
                if (len != 128) {
                    print_dbg("ERROR: Invalid ECDH share length: %d\n", len);
                    send_shutdown_signal();
                    break;
                }

                uint8_t* host_eph_pubkey = payload;
                uint8_t* host_signature = payload + 64;

                if (!crypto_ecdh_read_host_pubkey(g_protocol_state.host_permanent_pubkey)) {
                    print_dbg("ERROR: Failed to read host pubkey\n");
                    send_shutdown_signal();
                    break;
                }

                if (!crypto_ecdh_verify_signature(host_eph_pubkey, 64, host_signature,
                                          g_protocol_state.host_permanent_pubkey)) {
                    print_dbg("ERROR: Signature verification failed\n");
                    send_shutdown_signal();
                    break;
                }

                memcpy(g_protocol_state.received_host_eph_pubkey, host_eph_pubkey, 64);

                #ifndef UNIT_TEST
                // Only generate new ephemeral key if host-initiated (state 0x20)
                // At state 0x21 (token-initiated), we already have our key
                if (g_protocol_state.current_state == 0x20) {
                    if (!crypto_ecdh_generate_ephemeral_key(g_protocol_state.et_pubkey)) {
                        print_dbg("ERROR: Failed to generate ephemeral key\n");
                        send_shutdown_signal();
                        break;
                    }
                    print_dbg("Generated new ephemeral keypair\n");
                } else {
                    print_dbg("Using existing ephemeral key (token-initiated ECDH)\n");
                }

                uint8_t token_signature[64];
                if (!crypto_ecdh_sign_with_permanent_key(g_protocol_state.et_pubkey, 64, token_signature)) {
                    print_dbg("ERROR: Failed to sign ephemeral pubkey\n");
                    send_shutdown_signal();
                    break;
                }

                uint8_t shared_secret[32];
                if (!crypto_ecdh_compute_shared_secret(host_eph_pubkey, shared_secret)) {
                    print_dbg("ERROR: Failed to compute shared secret\n");
                    send_shutdown_signal();
                    break;
                }

                if (!crypto_derive_session_key(shared_secret, g_protocol_state.aes_session_key)) {
                    print_dbg("ERROR: Failed to derive session key\n");
                    send_shutdown_signal();
                    break;
                }

                // Check if we're responding to host-initiated ECDH (state 0x20)
                // or completing token-initiated ECDH (state 0x21)
                if (g_protocol_state.current_state == 0x20) {
                    // Host-initiated: Send our ECDH share
                    uint8_t response[128];
                    memcpy(response, g_protocol_state.et_pubkey, 64);
                    memcpy(response + 64, token_signature, 64);
                    send_message(T2H_ECDH_SHARE, response, 128);

                    print_dbg("Sent T2H_ECDH_SHARE (host-initiated ECDH)\n");
                } else {
                    // Token-initiated (state 0x21): We already sent T2H_ECDH_SHARE
                    // Just derive the new key and proceed
                    print_dbg("Derived new session key (token-initiated ECDH)\n");
                }
                #endif

                // State transition (moved outside UNIT_TEST guard)
                if (g_protocol_state.current_state == 0x20) {
                    g_protocol_state.current_state = 0x21;
                }

                #ifndef UNIT_TEST

                // Enable encryption flag once (stays true even during re-attestation)
                g_protocol_state.is_encrypted = true;

                pico_delay_ms(1000);
                protocol_send_channel_verification_challenge();
                #else
                // UNIT_TEST path: Set encryption flag
                g_protocol_state.is_encrypted = true;
                #endif
            }
            break;

        case H2T_CHANNEL_VERIFY_RESPONSE:
            if (g_protocol_state.current_state != 0x22) {
                print_dbg("ERROR: Channel verify response rejected (wrong state: 0x%02X)\n", g_protocol_state.current_state);
                send_shutdown_signal();
                break;
            }
            {
                if (len < 4) {
                    send_shutdown_signal();
                    break;
                }

                if (memcmp(payload, "pong", 4) != 0) {
                    send_shutdown_signal();
                    break;
                }

                // Advance to phase 2 - integrity verification
                g_protocol_state.current_state = 0x30;

                // delay here for some arbitrary time, host is sometimes slow with tpm
                pico_delay_ms(SLOW_HOST_COMPENSATION_MSECS);

                #ifndef UNIT_TEST
                g_protocol_state.integrity_challenge_nonce = get_rand_32();
                send_message(T2H_INTEGRITY_CHALLENGE, (uint8_t*)&g_protocol_state.integrity_challenge_nonce, 4);
                #else
                // In unit tests, just set a deterministic nonce
                g_protocol_state.integrity_challenge_nonce = 0x12345678;
                #endif
            }
            break;

        // ===== PHASE 2: INTEGRITY & BOOT =====
        case H2T_INTEGRITY_RESPONSE:
            if(g_protocol_state.current_state != 0x30){
                print_dbg("ERROR: Channel verify response rejected (wrong state: 0x%02X)\n", g_protocol_state.current_state);
                // disallowed state (desync)
                send_shutdown_signal();
                break; // should never reach
            }

            if(len != 96){
                send_message(T2H_NACK, NULL, 0);
                break;
            }

            print_dbg("Handler: H2T_INTEGRITY_RESPONSE started\n");
            // payload here contains hash + sig (hash_nonce)

            // separate the payload into hash and sig
            uint8_t hash[32];
            memcpy(hash, payload, 32);

            uint8_t signature[64];
            memcpy(signature, payload + 32, 64);

            bool result;
            if(!crypto_verify_integrity_challenge(hash,
                 g_protocol_state.integrity_challenge_nonce,
                 signature,
                 g_protocol_state.host_permanent_pubkey,
                &result)){
                print_dbg("ATECC error");
                send_message(T2H_ERROR, NULL, 0);
                break;
            }

            if(!result){
                // Signature verification failed - enter permanent halt state
                print_dbg("ERROR: Integrity challenge signature verification failed\n");
                protocol_enter_halt_spam_state();
                break; // should never reach
            }

            uint8_t p_golden_hash[32];
            bool atecc_status = crypto_get_golden_hash(p_golden_hash);

            if(!atecc_status){
                send_message(T2H_ERROR, NULL, 0);
                break;
            }

            if(memcmp(hash, p_golden_hash, 32)){
                // Golden hash mismatch - enter permanent halt state
                print_dbg("ERROR: Golden hash mismatch detected\n");
                protocol_enter_halt_spam_state();
                break; // should never reach
            }

            send_message(T2H_BOOT_OK, NULL, 0);

            // advance state and wait for ACK
            g_protocol_state.current_state = 0x32;
            break;

        case H2T_BOOT_OK_ACK:
            if(g_protocol_state.current_state != 0x32){
                print_dbg("ERROR: BOOT_OK_ACK rejected (wrong state: 0x%02X)\n", g_protocol_state.current_state);
                send_shutdown_signal();
                break;
            }

            // Start new session with configured timeout
            g_protocol_state.session_valid = true;
            g_protocol_state.session_start_timestamp = time_us_64();
            g_protocol_state.session_timeout_ms = 30000;  // Default: 30 seconds

            print_dbg("Session established - entering runtime (timeout: %dms)\n",
                      g_protocol_state.session_timeout_ms);
            g_protocol_state.current_state = 0x40;
            break;

        case H2T_INTEGRITY_FAIL_HALT:
            print_dbg("Handler: H2T_INTEGRITY_FAIL_HALT (not implemented)\n");
            break;

        case INTEGRITY_FAIL_ACK:
            print_dbg("Handler: INTEGRITY_FAIL_ACK (not implemented)\n");
            break;

        // ===== RUNTIME: HEARTBEAT =====
        case H2T_HEARTBEAT:
            // Only accept heartbeats in runtime state (0x40)
            if (g_protocol_state.current_state != 0x40) {
                print_dbg("ERROR: Heartbeat rejected (wrong state: 0x%02X)\n", g_protocol_state.current_state);
                break;
            }

            // Update last heartbeat timestamp
            g_protocol_state.last_hb_timstamp = time_us_64();
            g_protocol_state.missed_hb_count = 0;  // Reset missed count

            // Send ACK after a delay of 500ms to compensate for slow hosts
            pico_delay_ms(SLOW_HOST_COMPENSATION_MSECS);

            send_message(T2H_HEARTBEAT_ACK, NULL, 0);
            break;

        // ===== TESTING & DEBUG DO NOT INCLUDE IN PRODUCTION. =====
        #ifdef DEBUG
        case H2T_TEST_RANDOM_REQUEST:
            #ifndef UNIT_TEST
            {
                // Generate random number using ATECC608
                uint8_t random_data[32];
                ATCA_STATUS status = atcab_random(random_data);

                if (status == ATCA_SUCCESS) {
                    print_dbg("Generated 32 bytes of random data from ATECC608\n");
                    send_message(T2H_TEST_RANDOM_RESPONSE, random_data, sizeof(random_data));
                } else {
                    print_dbg("ERROR: Failed to generate random number, status: 0x%02X\n", status);
                }
            }
            #endif
            break;

        case H2T_DEBUG_SET_HOST_PUBKEY:
            #ifndef UNIT_TEST
            {
                if (len != 64) {
                    print_dbg("ERROR: Invalid host pubkey length: %d (expected 64)\n", len);
                    break;
                }

                // ATECC can only write 32 bytes at once, so write 64-byte pubkey in 2 blocks
                for (int block = 0; block < 2; block++) {
                    ATCA_STATUS status = atcab_write_zone(
                        ATCA_ZONE_DATA,     // Zone: data zone
                        8,                   // Slot 8
                        block,               // Block number (0 or 1)
                        0,                   // Offset 0
                        payload + (block * 32),  // 32 bytes per block
                        32                   // 32 bytes per block
                    );

                    if (status != ATCA_SUCCESS) {
                        print_dbg("ERROR: Failed to write host pubkey block %d, status: 0x%02X\n", block, status);
                        break;
                    }
                }

                memcpy(g_protocol_state.host_permanent_pubkey, payload, 64);
            }
            #endif
            break;

        case T2H_DEBUG_GET_TOKEN_PUBKEY:
            #ifndef UNIT_TEST
            {
                // Read token's permanent public key from Slot 0
                uint8_t token_pubkey[64];
                ATCA_STATUS status = atcab_get_pubkey(SLOT_PERMANENT_PRIVKEY, token_pubkey);

                if (status == ATCA_SUCCESS) {
                    send_message(T2H_DEBUG_GET_TOKEN_PUBKEY, token_pubkey, 64);
                } else {
                    print_dbg("ERROR: Failed to read token pubkey, status: 0x%02X\n", status);
                }
            }
            #endif
            break;
        case H2T_DEBUG_SET_GOLDEN_HASH:
            #ifndef UNIT_TEST
            {
                if(len != 32) {
                    send_message(T2H_ERROR, NULL, 0);
                    break;
                }

                bool atecc_status = crypto_set_golden_hash(payload);

                if(!atecc_status){
                    send_message(T2H_ERROR, NULL, 0);
                    break;
                }

                // Read back the golden hash to verify it was written correctly
                uint8_t p_golden_hash_retval[32];
                bool atecc_status1 = crypto_get_golden_hash(p_golden_hash_retval);

                if(!atecc_status1){
                    send_message(T2H_ERROR, NULL, 0);
                    break;
                }

                // Send back the read hash as acknowledgment
                send_message(H2T_DEBUG_SET_GOLDEN_HASH, p_golden_hash_retval, 32);
            }
            #endif
            break;
        #endif  // DEBUG

        // ===== INVALID MESSAGE TYPES =====
        // All other message types are T2H (Token to Host), so they should
        // not be received by the Token. This is an error condition.
        default:
            // An unexpected or invalid message type was received.
            // This could indicate a protocol error, a bug, or an attack.
            // DO NOT PROCEED.
            print_dbg("ERROR: Unexpected message type 0x%02X received (T2H or invalid)\n", msg_type);
            send_shutdown_signal();
            return;
    }
}

/**
 * Initiates channel verification by sending encrypted ping challenge.
 * Transitions state to 0x22 (channel verification), enabling encryption for all subsequent messages.
 */
void protocol_send_channel_verification_challenge(void) {
    #ifndef UNIT_TEST
    const uint8_t ping_message[] = {'p', 'i', 'n', 'g'};

    g_protocol_state.current_state = 0x22;
    send_message(T2H_CHANNEL_VERIFY_REQUEST, (uint8_t*)ping_message, sizeof(ping_message));
    #endif
}
