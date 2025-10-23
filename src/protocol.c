#include "protocol.h"
#include "serial.h"

#ifndef UNIT_TEST
#include "cryptoauthlib.h"
#endif

void handle_validated_message(message_type_t msg_type, uint8_t* payload, uint16_t len)
{
    // DEBUG: Log all received messages
    print_dbg("Received message type: 0x%02X, length: %d\n", msg_type, len);
    
    switch (msg_type)
    {
        // ===== PHASE 1: ECDH & CHANNEL ESTABLISHMENT =====
        case H2T_ECDH_SHARE:
            print_dbg("Handler: H2T_ECDH_SHARE (not implemented)\n");
            break;
        
        case H2T_CHANNEL_VERIFY_REQUEST:
            print_dbg("Handler: H2T_CHANNEL_VERIFY_REQUEST (not implemented)\n");
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