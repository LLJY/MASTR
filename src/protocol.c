#include "protocol.h"
#include "serial.h"
#include "crypt.h"

#ifndef UNIT_TEST
#include "cryptoauthlib.h"
#include "pico/sha256.h"
#endif

// Global protocol state
protocol_state_t protocol_state = {0};

// store golden hash and public key
void provision_protocol(){
    // do with placeholder data. generate this data using openssl, and sha256 and hardcode it in protocol.h for now...
    // future implementations will set this using the web server.
}

// delete golden hash and public key
void unprovision_protocol(){
    // clear slot 8 on the atecc
}

// check if the protocol is provisioned, if not perform some function...
bool protocol_check_provisioned(){
    // check if there is data in slot 8 (golden hash)
    // check if there is data in slot 8 (perma pubkey of host)

    // since slot 8 is the only general data slot with 416 bytes of storage

    // why not store both together, in the same slot?

    // layout of atecc slot 8:
    // <H_Pubkey>|<golden_hash>

    // receive both, verify, then store into protocol_state_t
    
    // TODO: Implement actual provisioning check
    return false; // Not provisioned yet
}

// to be run in main
// pull all the data from the ATECC to fill the protocol_state_t protocol_state struct.
void set_protocol_initial_state(){
    protocol_state.protocol_begin_timestamp = time_us_64();
}

/**
 * Handles incoming protocol messages after frame validation and decryption.
 * Enforces state machine progression and rejects out-of-order requests.
 * 
 * @param msg_type Message type from protocol enum
 * @param payload Decrypted message payload
 * @param len Payload length in bytes
 */
void handle_validated_message(message_type_t msg_type, uint8_t* payload, uint16_t len)
{
    #ifdef DEBUG
    print_dbg("Received message type: 0x%02X, length: %d\n", msg_type, len);
    #endif
    
    switch (msg_type)
    {
        case H2T_ECDH_SHARE:
            if (protocol_state.current_state != 0x20) {
                print_dbg("ERROR: ECDH share rejected (wrong state: 0x%02X)\n", protocol_state.current_state);
                send_shutdown_signal();
                break;
            }
            #ifndef UNIT_TEST
            {
                if (len != 128) {
                    print_dbg("ERROR: Invalid ECDH share length: %d\n", len);
                    send_shutdown_signal();
                    break;
                }
                
                uint8_t* host_eph_pubkey = payload;
                uint8_t* host_signature = payload + 64;
                
                if (!ecdh_read_host_pubkey(protocol_state.host_permanent_pubkey)) {
                    print_dbg("ERROR: Failed to read host pubkey\n");
                    send_shutdown_signal();
                    break;
                }
                
                if (!ecdh_verify_signature(host_eph_pubkey, 64, host_signature, 
                                          protocol_state.host_permanent_pubkey)) {
                    print_dbg("ERROR: Signature verification failed\n");
                    send_shutdown_signal();
                    break;
                }
                
                memcpy(protocol_state.received_host_eph_pubkey, host_eph_pubkey, 64);
                
                if (!ecdh_generate_ephemeral_key(protocol_state.et_pubkey)) {
                    print_dbg("ERROR: Failed to generate ephemeral key\n");
                    send_shutdown_signal();
                    break;
                }
                
                uint8_t token_signature[64];
                if (!ecdh_sign_with_permanent_key(protocol_state.et_pubkey, 64, token_signature)) {
                    print_dbg("ERROR: Failed to sign ephemeral pubkey\n");
                    send_shutdown_signal();
                    break;
                }
                
                uint8_t shared_secret[32];
                if (!ecdh_compute_shared_secret(host_eph_pubkey, shared_secret)) {
                    print_dbg("ERROR: Failed to compute shared secret\n");
                    send_shutdown_signal();
                    break;
                }
                
                if (!derive_session_key(shared_secret, protocol_state.aes_session_key)) {
                    print_dbg("ERROR: Failed to derive session key\n");
                    send_shutdown_signal();
                    break;
                }
                
                uint8_t response[128];
                memcpy(response, protocol_state.et_pubkey, 64);
                memcpy(response + 64, token_signature, 64);
                send_message(T2H_ECDH_SHARE, response, 128);
                
                protocol_state.current_state = 0x21;
                
                sleep_ms(1000);
                send_channel_verification_challenge();
            }
            #endif
            break;
        
        case H2T_CHANNEL_VERIFY_RESPONSE:
            if (protocol_state.current_state != 0x22) {
                print_dbg("ERROR: Channel verify response rejected (wrong state: 0x%02X)\n", protocol_state.current_state);
                send_shutdown_signal();
                break;
            }
            #ifndef UNIT_TEST
            {
                if (len < 4) {
                    print_dbg("ERROR: Invalid pong length: %d\n", len);
                    send_shutdown_signal();
                    break;
                }

                if (memcmp(payload, "pong", 4) != 0) {
                    print_dbg("ERROR: Invalid pong response\n");
                    send_shutdown_signal();
                    break;
                }

                protocol_state.current_state = 0x24;
                print_dbg("=== SECURE CHANNEL ESTABLISHED ===\n");
            }
            #endif
            break;
        
        // ===== PHASE 2: INTEGRITY & BOOT =====
        case H2T_INTEGRITY_RESPONSE:
            print_dbg("Handler: H2T_INTEGRITY_RESPONSE (not implemented)\n");
            break;
        
        case H2T_BOOT_OK_ACK:
            print_dbg("Handler: H2T_BOOT_OK_ACK (not implemented)\n");
            break;
        
        case H2T_INTEGRITY_FAIL_HALT:
            print_dbg("Handler: H2T_INTEGRITY_FAIL_HALT (not implemented)\n");
            break;
        
        case INTEGRITY_FAIL_ACK:
            print_dbg("Handler: INTEGRITY_FAIL_ACK (not implemented)\n");
            break;
        
        // ===== RUNTIME: HEARTBEAT =====
        case H2T_HEARTBEAT:
            print_dbg("Handler: H2T_HEARTBEAT (not implemented)\n");
            break;
        
        // ===== TESTING & DEBUG =====
        case H2T_TEST_RANDOM_REQUEST:
            print_dbg("Handler: H2T_TEST_RANDOM_REQUEST - Generating random number...\n");
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
            print_dbg("Handler: H2T_DEBUG_SET_HOST_PUBKEY - Storing host permanent pubkey...\n");
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
                
                print_dbg("Host permanent pubkey stored in ATECC Slot 8 (64 bytes)\n");
                memcpy(protocol_state.host_permanent_pubkey, payload, 64);
            }
            #endif
            break;
        
        case T2H_DEBUG_GET_TOKEN_PUBKEY:
            print_dbg("Handler: T2H_DEBUG_GET_TOKEN_PUBKEY - Reading token permanent pubkey...\n");
            #ifndef UNIT_TEST
            {
                // Read token's permanent public key from Slot 0
                uint8_t token_pubkey[64];
                ATCA_STATUS status = atcab_get_pubkey(SLOT_PERMANENT_PRIVKEY, token_pubkey);
                
                if (status == ATCA_SUCCESS) {
                    print_dbg("Token permanent pubkey read from ATECC Slot 0\n");
                    send_message(T2H_DEBUG_GET_TOKEN_PUBKEY, token_pubkey, 64);
                } else {
                    print_dbg("ERROR: Failed to read token pubkey, status: 0x%02X\n", status);
                }
            }
            #endif
            break;
        
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
void send_channel_verification_challenge() {
    #ifndef UNIT_TEST
    const uint8_t ping_message[] = {'p', 'i', 'n', 'g'};
    
    protocol_state.current_state = 0x22;
    send_message(T2H_CHANNEL_VERIFY_REQUEST, (uint8_t*)ping_message, sizeof(ping_message));
    #endif
}
