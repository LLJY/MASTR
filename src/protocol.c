#include "protocol.h"
#include "serial.h"

void handle_validated_message(message_type_t msg_type, uint8_t* payload, uint16_t len)
{
    switch (msg_type)
    {
        case H2T_ECDH_SHARE:
            break;
        case H2T_CHANNEL_VERIFY_REQUEST:
            break;
        case H2T_INTEGRITY_RESPONSE:
            break;
        case H2T_HEARTBEAT:
            break;
            // ----------------------------------------------------------------
            // All other message types are T2H (Token to Host), so they should
            // not be received by the Token. This is an error condition.
            // ----------------------------------------------------------------
        default:
            // An unexpected or invalid message type was received.
            // This could indicate a protocol error, a bug, or an attack.
            // DO NOT PROCEED.
            send_shutdown_signal();
            return;
    }
}