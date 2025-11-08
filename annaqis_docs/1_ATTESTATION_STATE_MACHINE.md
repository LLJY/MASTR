# MASTR Attestation State Machine - Complete Analysis

## Overview

MASTR is a token attestation system with three main phases:
1. **Mutual Attestation & Secure Channel Establishment** (ECDH-based)
2. **Integrity Verification & Boot Authorization**
3. **Runtime with Heartbeat Monitoring**

The token starts in a **pairing state (0x20)** waiting for the host to initiate ECDH key exchange.

---

## Protocol Phases

### Phase 1: Mutual Attestation & Secure Channel Establishment

```
State 0x20: WAITING FOR HOST ECDH SHARE (Initial State)
    ↓ [Host sends H2T_ECDH_SHARE]
    ├─ Verify host ephemeral pubkey signature
    ├─ Generate token ephemeral key (host-initiated path)
    ├─ Compute shared secret via ECDH
    ├─ Derive AES session key
    └─ Send T2H_ECDH_SHARE response
    ↓
State 0x21: ECDH COMPLETE
    ├─ Encryption enabled
    ├─ Send T2H_CHANNEL_VERIFY_REQUEST (encrypted "ping")
    ↓
State 0x22: CHANNEL VERIFICATION (Ping/Pong Challenge)
    ↓ [Host responds with H2T_CHANNEL_VERIFY_RESPONSE]
    └─ Verify decrypted response is "pong"
```

**Duration**: ~1-2 seconds
**Security**: Mutual ECDH with signature verification

### Phase 2: Integrity Verification & Boot Authorization

```
State 0x30: INTEGRITY CHALLENGE
    ├─ Token generates random nonce
    └─ Send T2H_INTEGRITY_CHALLENGE (encrypted nonce)
    ↓
State 0x30: AWAITING INTEGRITY RESPONSE
    ↓ [Host sends H2T_INTEGRITY_RESPONSE]
    ├─ Verify signature with host's permanent pubkey
    ├─ Verify hash matches golden hash
    ├─ IF VERIFICATION FAILS → Enter permanent halt (0xFF)
    └─ IF VERIFICATION PASSES → Send T2H_BOOT_OK
    ↓
State 0x32: BOOT_OK SENT (Waiting for Host ACK)
    ↓ [Host acknowledges with H2T_BOOT_OK_ACK]
    └─ Create new session with 30-second timeout
```

**Duration**: ~1-2 seconds
**Security**: Software integrity verification with nonce replay protection

### Phase 3: Runtime - Heartbeat Monitoring

```
State 0x40: RUNTIME - HEARTBEAT MONITORING
    ├─ Session is valid (session_valid = true)
    ├─ Encrypted communication active
    ├─ 30-second inactivity timeout monitored by watchdog
    ↓ [Periodic H2T_HEARTBEAT messages]
    ├─ Token responds with T2H_HEARTBEAT_ACK
    ├─ Reset missed heartbeat count
    └─ Update last_hb_timestamp
    ↓
[On Timeout] → Trigger re-attestation (back to State 0x20)
```

**Duration**: Until timeout or re-attestation
**Security**: Session timeout with watchdog-triggered re-attestation

---

## Re-attestation Flow

When 30-second heartbeat timeout expires:

```
Watchdog Task (runs every 1 second)
    ↓ Detects timeout in state 0x40
    ├─ Call protocol_trigger_reattestation()
    ├─ Invalidate current session (keeps old key!)
    ├─ Generate new ephemeral keypair
    ├─ Sign new ephemeral pubkey
    ├─ Send T2H_ECDH_SHARE (token-initiated)
    └─ Set state to 0x21
    ↓
State 0x21: RE-ATTESTATION IN PROGRESS
    ├─ Encryption still active (old session key)
    ├─ Different from initial 0x20 (host initiates, token-initiated here)
    ↓ [Host responds with H2T_ECDH_SHARE (new ephemeral)]
    ├─ Verify signature with old key
    ├─ Skip ephemeral key generation (already have new one)
    ├─ Compute new shared secret
    ├─ Derive new session key
    └─ Proceed directly to channel verification
```

**Key Feature**: Old session key retained during re-attestation, preventing loss of encrypted communication.

---

## State Values & Meanings

| State | Hex  | Phase | Description | Encrypted |
|-------|------|-------|-------------|-----------|
| 0x20  | 0x20 | 1     | Initial ECDH - Host initiates | ❌ No |
| 0x21  | 0x21 | 1     | ECDH complete or re-attestation in progress | ✅ Yes* |
| 0x22  | 0x22 | 1     | Channel verification (ping/pong) | ✅ Yes |
| 0x30  | 0x30 | 2     | Integrity challenge sent | ✅ Yes |
| 0x32  | 0x32 | 2     | Boot OK sent, awaiting ACK | ✅ Yes |
| 0x40  | 0x40 | 3     | Runtime - heartbeat monitoring | ✅ Yes |
| 0xFF  | 0xFF | ~     | Permanent halt (integrity failure) | N/A |

*At state 0x21 during re-attestation, encryption remains active using the previous session key.

---

## Message Types

### Phase 1: ECDH Exchange
- **H2T_ECDH_SHARE (0x20)**: Host's ephemeral pubkey + signature
- **T2H_ECDH_SHARE (0x21)**: Token's ephemeral pubkey + signature
- **T2H_CHANNEL_VERIFY_REQUEST (0x22)**: Encrypted "ping" challenge
- **H2T_CHANNEL_VERIFY_RESPONSE (0x23)**: Encrypted "pong" response

### Phase 2: Integrity Verification
- **T2H_INTEGRITY_CHALLENGE (0x30)**: Random nonce
- **H2T_INTEGRITY_RESPONSE (0x31)**: Hash + signature over (hash || nonce)
- **T2H_BOOT_OK (0x32)**: Boot authorization granted
- **H2T_BOOT_OK_ACK (0x34)**: Host acknowledges

### Phase 3: Runtime
- **H2T_HEARTBEAT (0x40)**: Keep-alive message
- **T2H_HEARTBEAT_ACK (0x41)**: Heartbeat acknowledgement

### Error Handling
- **T2H_ERROR (0x00)**: Generic error
- **T2H_NACK (0x01)**: Request rejected
- **T2H_INTEGRITY_FAIL_HALT (0x33)**: Integrity failure - permanent halt

---

## Security Checkpoints

### 1. ECDH Signature Verification (State 0x20/0x21)
```c
ecdh_verify_signature(host_eph_pubkey, 64, host_signature, 
                      protocol_state.host_permanent_pubkey)
```
- Ensures host's ephemeral key comes from the legitimate host
- Uses host's permanent pubkey stored in ATECC Slot 8
- Failure → Shutdown signal

### 2. Session Key Derivation (State 0x21)
```c
ecdh_compute_shared_secret(host_eph_pubkey, shared_secret)
derive_session_key(shared_secret, protocol_state.aes_session_key)
```
- Bidirectional ECDH ensures mutual agreement on session key
- Derived session key never transmitted in clear
- Enables encrypted communication from state 0x22 onward

### 3. Channel Verification (State 0x22)
```c
send_message(T2H_CHANNEL_VERIFY_REQUEST, "ping", 4)  // Encrypted
// Host responds with "pong" (decrypted)
```
- Proves both sides can encrypt/decrypt with derived key
- First test of the newly established secure channel
- Failure → Shutdown signal

### 4. Integrity Verification (State 0x30)
```c
crypto_verify_integrity_challenge(hash, nonce, signature, host_permanent_pubkey)
memcmp(hash, golden_hash)  // Golden hash stored on ATECC
```
- Nonce prevents replay attacks
- Hash prevents tampering with host software
- Signature proves host controls its private key
- Failure → Permanent halt (0xFF)

### 5. Boot Authorization (State 0x32→0x40)
- Host must acknowledge boot permission
- Session timeout (30s) enforced by watchdog
- Requires periodic heartbeats to stay in runtime state

---

## Failure Modes

### Soft Failure: Session Timeout
- **Trigger**: No heartbeat for 30 seconds
- **Action**: Watchdog triggers re-attestation
- **Recovery**: Host can re-attest within timeout period
- **State Transition**: 0x40 → (re-attest) → 0x40

### Hard Failure: Integrity Mismatch
- **Trigger**: Golden hash doesn't match received hash
- **Action**: Enter permanent halt state
- **Recovery**: **NONE** - token spams `T2H_INTEGRITY_FAIL_HALT` indefinitely
- **State Transition**: 0x30 → 0xFF (permanent)

### Hard Failure: Signature Verification Failed
- **Trigger**: Any signature verification failure (ECDH or integrity)
- **Action**: Send `send_shutdown_signal()` → permanent halt
- **Recovery**: **NONE**
- **State Transition**: Any state → 0xFF (via shutdown)

---

## Critical Design Insight: Encryption Persistence

The code has an **important asymmetry**:

```c
protocol_state.is_encrypted = true;  // Set ONCE and never reset
```

This means:
- **First ECDH (0x20→0x21)**: Encryption becomes enabled
- **During re-attestation (0x40→0x20→0x21)**: Encryption **remains active** using the old session key
- The old key is kept until the **new** session key is successfully derived
- This prevents loss of encrypted communication during re-attestation

**Benefit**: Re-attestation can happen over encrypted channel with old key as fallback.

---

## Session Management

### Session Creation (State 0x32→0x40)
```c
protocol_state.session_valid = true;
protocol_state.session_start_timestamp = time_us_64();
protocol_state.session_timeout_ms = 30000;  // Default: 30 seconds
```

### Session Validation
```c
bool protocol_is_session_valid(void) {
    if (!protocol_state.session_valid) {
        return false;
    }
    
    uint64_t current_time = time_us_64();
    uint64_t elapsed_ms = (current_time - protocol_state.session_start_timestamp) / 1000;
    
    return elapsed_ms < protocol_state.session_timeout_ms;
}
```

### Session Invalidation (Re-attestation)
```c
protocol_state.session_valid = false;
// DO NOT clear session key yet - keep old key for encrypted communication
protocol_state.current_state = 0x20;
```

---

## Global State Structure

```c
typedef struct{
    uint64_t protocol_begin_timestamp;
    uint8_t current_state;                      // Current protocol state
    uint64_t current_state_begin_timestamp;
    
    // Permanent public keys
    uint8_t host_permanent_pubkey[64];
    
    // Ephemeral ECDH keys
    uint8_t et_pubkey[64];
    uint8_t received_host_eph_pubkey[64];
    
    // Derived session key
    uint8_t aes_session_key[16];
    
    // Channel verification challenge
    uint8_t channel_challenge[32];
    
    // Integrity verification
    uint32_t integrity_challenge_nonce;
    
    // Heartbeat tracking
    uint8_t missed_hb_count;
    uint32_t hb_nonce;
    uint64_t last_hb_timestamp;
    
    // Session management
    bool is_encrypted;
    bool session_valid;
    uint64_t session_start_timestamp;
    uint32_t session_timeout_ms;
    uint64_t last_watchdog_check;
    bool in_halt_state;
} protocol_state_t;
```

---

## Timeline Example

```
T=0s:     Token starts, waits at state 0x20
T=0.1s:   Host sends H2T_ECDH_SHARE
T=0.2s:   Token sends T2H_ECDH_SHARE (state 0x21)
T=0.3s:   Token sends T2H_CHANNEL_VERIFY_REQUEST (state 0x22)
T=0.4s:   Host responds H2T_CHANNEL_VERIFY_RESPONSE
T=0.5s:   Token sends T2H_INTEGRITY_CHALLENGE (state 0x30)
T=0.6s:   Host responds H2T_INTEGRITY_RESPONSE
T=0.7s:   Token sends T2H_BOOT_OK (state 0x32)
T=0.8s:   Host responds H2T_BOOT_OK_ACK
T=0.9s:   Token enters runtime (state 0x40, session valid)
T=1.0s:   Host sends periodic H2T_HEARTBEAT
T=1.1s:   Token responds T2H_HEARTBEAT_ACK
...
T=30.0s:  Heartbeat timeout!
T=30.1s:  Watchdog triggers re-attestation
T=30.2s:  Token back to state 0x20, sends T2H_ECDH_SHARE
...
```

---

## Summary

✅ **Starting State**: 0x20 (Host-initiated ECDH pairing)  
✅ **Success Path**: 0x20 → 0x21 → 0x22 → 0x30 → 0x32 → 0x40 (runtime)  
✅ **Timeout Path**: 0x40 → re-attestation → 0x20 → 0x21 → ... → 0x40  
✅ **Failure Path**: Any state → 0xFF (permanent halt, no recovery)  
✅ **Encryption**: Enabled from state 0x21 onward, persistent through re-attestation  
✅ **Session**: 30-second timeout with watchdog monitoring  

The protocol ensures mutual authentication, integrity verification, and continuous session validation for secure token attestation.
