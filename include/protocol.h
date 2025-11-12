#include <stdint.h>
#include <stdbool.h>
#ifndef PROTOCOL_H
#define PROTOCOL_H

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
    // Class 0: System Control Messages
    // --------------------------------------------------------------------

    /**
     * @brief T2H: Generic error message from Token
     */
    T2H_ERROR = 0x00,

    /**
     * @brief T2H: Negative acknowledgement - request rejected/failed
     */
    T2H_NACK = 0x01,

    // --------------------------------------------------------------------
    // Phase 1: Mutual Attestation & Secure Channel Establishment
    // --------------------------------------------------------------------

    /**
     * @brief H2T: Host sends its ephemeral public key and a signature over it.
     * \n payload: A 64-byte uncompressed P256 public key (EH_Pubkey), followed by its signature.
     */
    H2T_ECDH_SHARE = 0x20,

    /**
     * @brief T2H: Token, after verifying the Host's share, sends its own
     *        ephemeral public key and a signature over it.
     * \n payload: A 64-byte uncompressed P256 public key (ET_Pubkey), followed by its signature.
     */
    T2H_ECDH_SHARE = 0x21,

    /**
     * @brief T2H: Token sends an encrypted challenge to verify the newly derived SessionKey.
     * \n payload: An encrypted 32-byte random challenge.
     */
    T2H_CHANNEL_VERIFY_REQUEST = 0x22,

    /**
     * @brief H2T: Host decrypts the challenge and returns an encrypted hash.
     * \n payload: An encrypted SHA256 hash of the challenge.
     */
    H2T_CHANNEL_VERIFY_RESPONSE = 0x23,


    // --------------------------------------------------------------------
    // Phase 2: Integrity Verification & Runtime Guard
    // --------------------------------------------------------------------

    /**
     * @brief T2H: The Token challenges the Host to prove its software integrity.
     * \n payload: A random nonce.
     */
    T2H_INTEGRITY_CHALLENGE = 0x30,

    /**
     * @brief H2T: The Host's response, containing the measured hash and a signature
     *        over the hash and the received nonce.
     * \n payload: A 32-byte hash followed by the signature.
     */
    H2T_INTEGRITY_RESPONSE = 0x31,
    
    /**
     * @brief T2H: The Token signals to the Host that the integrity check passed
     *        and it is authorized to continue booting.
     * \n payload: (Empty)
     */
    T2H_BOOT_OK = 0x32,

    /**
     * @brief T2H: The Token signals an integrity check failure and commands an
     *        immediate halt of the boot process.
     * \n payload: (Empty)
     */
    T2H_INTEGRITY_FAIL_HALT = 0x33,

    /**
     * @brief H2T: Host acknowledges successful boot authorization
     * \n payload: (Empty)
     */
    H2T_BOOT_OK_ACK = 0x34,

    H2T_INTEGRITY_FAIL_HALT = 0x35,

    // mutual ACK for integrity fail.
    INTEGRITY_FAIL_ACK = 0X36,


    // --------------------------------------------------------------------
    // Runtime Heartbeat
    // --------------------------------------------------------------------

    /**
     * @brief H2T: A simple periodic heartbeat message from the Host to the Token.
     * \n payload: (Can be empty or contain a sequence number).
     */
    H2T_HEARTBEAT = 0x40,

    /**
     * @brief T2H: The Token's acknowledgement of a successful heartbeat.
     * \n payload: (Empty)
     */
    T2H_HEARTBEAT_ACK = 0x41,


    // --------------------------------------------------------------------
    // Testing & Debug Commands (counting down from 0xFE)
    // --------------------------------------------------------------------

    #ifdef DEBUG
    /**
     * @brief Debug message - print to user console
     * \n payload: UTF-8 string
     */
    DEBUG_MSG = 0xFE,

    /**
     * @brief H2T: Request a random number from the ATECC608 (for testing)
     * \n payload: (Empty)
     */
    H2T_TEST_RANDOM_REQUEST = 0xFD,

    /**
     * @brief T2H: Response containing a random number from ATECC608
     * \n payload: 32 bytes of random data
     */
    T2H_TEST_RANDOM_RESPONSE = 0xFC,

    /**
     * @brief H2T: Host sends its permanent public key for debugging/setup
     * \n payload: 64-byte P-256 public key
     */
    H2T_DEBUG_SET_HOST_PUBKEY = 0xFB,

    /**
     * @brief T2H: Token sends its permanent public key for debugging/setup
     * \n payload: 64-byte P-256 public key
     */
    T2H_DEBUG_GET_TOKEN_PUBKEY = 0xFA,

    H2T_DEBUG_SET_GOLDEN_HASH = 0xF9
    #endif

} message_type_t;
#pragma pack(pop)

typedef struct{
    uint64_t protocol_begin_timestamp;

    // @brief except for phase 2, only store the high nibble (msg_type >> 4) of the state.
    // 0xFF will represent a NACK shutdown state, which means we will freeze the MCU in a permenant while(true)
    // and plumb the software to never respond to anything ever again, this is out SHUTDOWN state (0XFF)
    uint8_t current_state;
    uint64_t current_state_begin_timestamp;
    
    // Permanent public keys (stored persistently)
    uint8_t host_permanent_pubkey[64];  // Host's permanent pubkey (from ATECC Slot 8)
    
    // Ephemeral ECDH keys (session-specific)
    uint8_t et_pubkey[64];               // Token's ephemeral pubkey
    uint8_t received_host_eph_pubkey[64]; // Host's ephemeral pubkey
    
    // Derived session key
    uint8_t aes_session_key[16];
    
    // Channel verification challenge
    uint8_t channel_challenge[32];       // Random challenge sent to host TODO REMOVE

    // nonce sent during integrity challenge
    uint32_t integrity_challenge_nonce;

    // missed hb will increment if the expected hearbeat time is exceeded.
    uint8_t missed_hb_count;
    uint32_t hb_nonce;
    uint64_t last_hb_timstamp;

    // Session management - decoupled from state machine
    bool is_encrypted;                   // Once true, always encrypted (even during re-attestation)
    bool session_valid;                  // Current session validity
    uint64_t session_start_timestamp;    // When current session began
    uint32_t session_timeout_ms;         // Configurable timeout (default: 30000ms = 30s)
    uint64_t last_watchdog_check;        // Last watchdog execution timestamp
    bool in_halt_state;                  // Permanent T2H_INTEGRITY_FAIL_HALT spam mode

} protocol_state_t;

// Global protocol state (defined in protocol.c)
extern protocol_state_t g_protocol_state;

// forward declarations
void protocol_provision(const uint8_t* p_golden_hash, const uint8_t* p_pub_key, const uint8_t golden_hash_len, const uint8_t pub_key_len);
void protocol_unprovision();
bool protocol_check_provisioned();
void protocol_handle_validated_message(message_type_t msg_type, uint8_t* payload, uint16_t len);
void protocol_send_channel_verification_challenge();

// Session management functions
void protocol_invalidate_session(void);
void protocol_trigger_reattestation(void);
bool protocol_is_session_valid(void);
void protocol_panic(const char* reason);
void protocol_enter_halt_spam_state(void);

// Watchdog task
void watchdog_task(void *params);

#endif