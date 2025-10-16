#include <stdint.h>
#ifndef PROTOCOL_H
#define PROTOCOL_H
#define DEBUG
// tell the compiler to ALWAYS pack the struct
// so the memory layout is contiguous
#pragma pack(push, 1)

/**
 * @brief Defines all possible message types for the Host-Token protocol, derived from the
 *        provided architectural diagrams.
 * 
 * AI Use Declaration: The documentation here was written AI-assisted.
 *
 * H2T = Host to Token
 * T2H = Token to Host
 */
typedef enum {
    // --------------------------------------------------------------------
    // Phase 1: Mutual Attestation & Secure Channel Establishment
    // --------------------------------------------------------------------

    /**
     * @brief H2T: Host sends its ephemeral public key and a signature over it.
     * @payload A 64-byte uncompressed P256 public key (EH_Pubkey), followed by its signature.
     */
    H2T_ECDH_SHARE = 0x20,

    /**
     * @brief T2H: Token, after verifying the Host's share, sends its own
     *        ephemeral public key and a signature over it.
     * @payload A 64-byte uncompressed P256 public key (ET_Pubkey), followed by its signature.
     */
    T2H_ECDH_SHARE = 0x21,

    /**
     * @brief H2T: Host sends an encrypted ping to verify the newly derived SessionKey.
     * @payload An encrypted block of known data (e.g., a 16-byte ping).
     */
    H2T_CHANNEL_VERIFY_REQUEST = 0x22,

    /**
     * @brief T2H: Token decrypts the ping, verifies it, and returns an encrypted pong.
     * @payload An encrypted block of known data (e.g., a 16-byte pong).
     */
    T2H_CHANNEL_VERIFY_RESPONSE = 0x23,


    // --------------------------------------------------------------------
    // Phase 2: Integrity Verification & Runtime Guard
    // --------------------------------------------------------------------

    /**
     * @brief T2H: The Token challenges the Host to prove its software integrity.
     * @payload A random nonce.
     */
    T2H_INTEGRITY_CHALLENGE = 0x30,

    /**
     * @brief H2T: The Host's response, containing the measured hash and a signature
     *        over the hash and the received nonce.
     * @payload A 32-byte hash followed by the signature.
     */
    H2T_INTEGRITY_RESPONSE = 0x31,
    
    /**
     * @brief T2H: The Token signals to the Host that the integrity check passed
     *        and it is authorized to continue booting.
     * @payload (Empty)
     */
    T2H_BOOT_OK = 0x32,

    /**
     * @brief T2H: The Token signals an integrity check failure and commands an
     *        immediate halt of the boot process.
     * @payload (Empty)
     */
    T2H_INTEGRITY_FAIL_HALT = 0x33,


    // --------------------------------------------------------------------
    // Runtime Heartbeat
    // --------------------------------------------------------------------

    /**
     * @brief H2T: A simple periodic heartbeat message from the Host to the Token.
     * @payload (Can be empty or contain a sequence number).
     */
    H2T_HEARTBEAT = 0x40,

    /**
     * @brief T2H: The Token's acknowledgement of a successful heartbeat.
     * @payload (Empty)
     */
    T2H_HEARTBEAT_ACK = 0x41,

    #ifdef DEBUG
    /**
     * @brief a debug byte message, just print to the user.
     */
    DEBUG_MSG = 0xFE,
    #endif

} message_type_t;

#pragma pack(pop)

void handle_validated_message(message_type_t msg_type, uint8_t* payload, uint16_t len);
#endif