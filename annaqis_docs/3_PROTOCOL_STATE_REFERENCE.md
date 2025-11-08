# Protocol State Reference

A complete reference guide to all MASTR protocol states, transitions, and message types.

## State Values Reference

| State | Hex  | Phase | Name | Encrypted | Initial |
|-------|------|-------|------|-----------|---------|
| `H2T_ECDH_SHARE` | 0x20 | 1 | ECDH - Host Initiates | ❌ | ✓ Yes |
| `T2H_ECDH_SHARE` | 0x21 | 1 | ECDH Complete | ✅ | |
| `T2H_CHANNEL_VERIFY_REQUEST` | 0x22 | 1 | Channel Verification | ✅ | |
| `T2H_INTEGRITY_CHALLENGE` | 0x30 | 2 | Integrity Verification | ✅ | |
| `T2H_BOOT_OK` | 0x32 | 2 | Boot Approved | ✅ | |
| `T2H_RUNTIME_HEARTBEAT` | 0x40 | 3 | Runtime Mode | ✅ | |
| `T2H_INTEGRITY_FAIL_HALT` | 0xFF | ~ | Permanent Halt | N/A | |

## Phase 1: Secure Channel Establishment

### State 0x20 - Initial ECDH (Host Initiates)
**Purpose**: Establish secure communication channel

**Flow**:
1. Host sends `H2T_ECDH_SHARE` with ephemeral public key + signature
2. Token verifies signature with host's permanent pubkey
3. Token generates its ephemeral keypair
4. Token computes shared secret via ECDH
5. Token derives AES session key from shared secret
6. Token responds with `T2H_ECDH_SHARE`

**Result**: Both parties have identical session key

**Code Reference**: `handle_validated_message()` in `protocol.c`

### State 0x21 - ECDH Complete
**Purpose**: Initiate channel verification

**Flow**:
1. `is_encrypted` flag set to `true`
2. Token sends `T2H_CHANNEL_VERIFY_REQUEST` with "ping" (encrypted)
3. Host responds with "pong" (encrypted)
4. Token verifies response is "pong"
5. If successful, proceed to integrity verification

**Result**: Both sides confirmed they can encrypt/decrypt with shared session key

### State 0x22 - Channel Verification
**Purpose**: Confirm bidirectional encrypted communication

**Flow**:
1. Token receives `H2T_CHANNEL_VERIFY_RESPONSE`
2. Decrypt and verify payload is "pong"
3. If verification passes, transition to Phase 2
4. If verification fails, send shutdown signal

**Result**: Ready for integrity verification

## Phase 2: Integrity Verification & Boot Authorization

### State 0x30 - Integrity Challenge
**Purpose**: Verify host software integrity

**Flow**:
1. Token generates random nonce
2. Token sends `T2H_INTEGRITY_CHALLENGE` with encrypted nonce
3. Host computes: `hash = SHA256(host_software)`
4. Host creates: `signature = sign(hash || nonce)`
5. Host sends `H2T_INTEGRITY_RESPONSE` with hash + signature
6. Token verifies signature using host's permanent pubkey
7. Token compares received hash with golden hash (stored on ATECC)

**Security Features**:
- Nonce prevents replay attacks
- Hash ensures no software tampering
- Signature proves host control of private key
- Golden hash stored in ATECC hardware

**Verification Result**:
- ✓ Pass: Send `T2H_BOOT_OK`, move to state 0x32
- ✗ Fail: Send `T2H_INTEGRITY_FAIL_HALT`, enter permanent halt state 0xFF

### State 0x32 - Boot OK Sent
**Purpose**: Wait for host acknowledgment before entering runtime

**Flow**:
1. Token sends `T2H_BOOT_OK` (encrypted)
2. Host sends `H2T_BOOT_OK_ACK` (encrypted)
3. Token creates new session:
   - `session_valid = true`
   - `session_timestamp = now()`
   - Timeout = 30 seconds
4. Transition to Phase 3 (runtime)

## Phase 3: Runtime - Heartbeat Monitoring

### State 0x40 - Runtime Heartbeat
**Purpose**: Monitor liveness and trigger re-attestation on timeout

**Flow**:
1. Host sends periodic `H2T_HEARTBEAT` messages (recommended: every 10 seconds)
2. Token responds with `T2H_HEARTBEAT_ACK` (encrypted)
3. Token resets missed heartbeat counter
4. Token updates last heartbeat timestamp

**Session Timeout**:
- Window: 30 seconds
- Checked by watchdog task every 1 second
- When exceeded: Call `protocol_trigger_reattestation()`

**Reattestation Flow** (when timeout occurs):
1. Invalidate current session (but keep session key!)
2. Generate new ephemeral keypair
3. Send `T2H_ECDH_SHARE` (token-initiated this time)
4. Transition to state 0x21 (encrypted with old key)
5. Cycle continues: 0x21 → 0x22 → 0x30 → 0x32 → 0x40

## Failure States

### State 0xFF - Permanent Halt
**Purpose**: Stop all communication after fatal security failure

**Entry Conditions**:
1. Integrity hash mismatch (software tampering detected)
2. Signature verification failure (cryptographic forgery attempt)
3. Explicit shutdown signal

**Behavior**:
- Token repeatedly sends `T2H_INTEGRITY_FAIL_HALT` message
- No other messages processed
- No recovery mechanism
- **Device restart required**

**Message Content**: Indicates failure reason (code value in message)

## Message Type Reference

### Host to Token (H2T) Messages

| Message | Code | Phase | Payload | Response |
|---------|------|-------|---------|----------|
| `H2T_ECDH_SHARE` | 0x01 | 1 | Ephemeral pubkey (64B) + signature (64B) | `T2H_ECDH_SHARE` |
| `H2T_CHANNEL_VERIFY_RESPONSE` | 0x02 | 1 | "pong" payload | → Phase 2 |
| `H2T_INTEGRITY_RESPONSE` | 0x03 | 2 | Hash (32B) + signature (64B) | `T2H_BOOT_OK` or `T2H_INTEGRITY_FAIL_HALT` |
| `H2T_BOOT_OK_ACK` | 0x04 | 2 | (empty) | → State 0x40 |
| `H2T_HEARTBEAT` | 0x05 | 3 | (empty) | `T2H_HEARTBEAT_ACK` |

### Token to Host (T2H) Messages

| Message | Code | Phase | Payload | Meaning |
|---------|------|-------|---------|---------|
| `T2H_ECDH_SHARE` | 0x81 | 1 | Ephemeral pubkey (64B) + signature (64B) | ECDH phase 1 complete |
| `T2H_CHANNEL_VERIFY_REQUEST` | 0x82 | 1 | "ping" payload | Test encryption channel |
| `T2H_INTEGRITY_CHALLENGE` | 0x83 | 2 | Nonce (16B) | Challenge for integrity proof |
| `T2H_BOOT_OK` | 0x84 | 2 | (empty) | Boot permission granted |
| `T2H_HEARTBEAT_ACK` | 0x85 | 3 | (empty) | Liveness acknowledgment |
| `T2H_INTEGRITY_FAIL_HALT` | 0xFF | ~ | Error code | Fatal integrity failure |

## Critical Implementation Details

### Encryption Behavior
```c
protocol_state.is_encrypted = true;  // Set ONCE at end of 0x21
                                      // Never reset thereafter
```
- At state 0x20: Messages are **plain text**
- At state 0x21+: Messages are **encrypted**
- During re-attestation: Uses **old session key** until new one derived
- This prevents communication loss during key refresh

### Session Management
```c
protocol_state.session_valid = true;   // Set at state 0x40 entry
protocol_state.session_timestamp = now();
protocol_state.session_timeout_seconds = 30;
```
- Checked every 1 second by watchdog
- `time_now - session_timestamp > 30` triggers re-attestation
- Session not destroyed; just flagged invalid
- New session created after successful re-attestation

### Key Storage
- **Host permanent pubkey**: ATECC Slot 8 (verified in 0x20)
- **Golden hash**: ATECC Slot 9 (verified in 0x30)
- **Session key**: RAM (derived from ECDH shared secret)
- **Ephemeral keys**: Generated fresh each ECDH cycle

### Nonce for Re-attestation Prevention
- Generated fresh for each integrity challenge (state 0x30)
- Prevents replay of old integrity responses
- Checked by host but not enforced in token (host's responsibility)

## State Diagram

```
                    ┌─────────────────┐
                    │    START (0x20)  │ ← Initial state
                    └────────┬─────────┘
                             │ H2T_ECDH_SHARE
                             ↓
                    ┌─────────────────┐
                    │   0x21 (ECDH)   │ ← Encryption enabled
                    └────────┬─────────┘
                             │ Verify H2T_CHANNEL_VERIFY_RESPONSE
                             ↓
                    ┌─────────────────┐
                    │  0x22 (Verify)  │ ← Ping/Pong challenge
                    └────────┬─────────┘
                             │ Success
                             ↓
                    ┌─────────────────┐
                    │  0x30 (Integrity)│ ← Generate nonce
                    └────────┬─────────┘
                             │ H2T_INTEGRITY_RESPONSE
                             ├─ Success ─┐
                             │           ↓
                             │    ┌──────────────┐
                             │    │ 0x32 (Boot) │ ← Send permission
                             │    └────┬─────────┘
                             │         │ H2T_BOOT_OK_ACK
                             │         ↓
                             │    ┌──────────────┐
                             │    │  0x40 (Run)  │ ← Runtime/Heartbeat
                             │    └─────┬────────┘
                             │          │ timeout → Re-attest
                             │          └─┐
                             └─────────────┘
                             │
                    Failure   ↓
                             │
                    ┌──────────────────┐
                    │  0xFF (Halt)     │ ← Permanent halt
                    └──────────────────┘
```

## Quick Lookup: What Happens When...

**Question**: I got a `T2H_INTEGRITY_FAIL_HALT` message?
- **Answer**: Integrity verification failed. Hash mismatch or bad signature. Device must restart.

**Question**: Why does my token keep asking for ECDH?
- **Answer**: It's re-attesting because heartbeats stopped for 30 seconds. Send periodic heartbeats from host.

**Question**: When should I send heartbeats?
- **Answer**: Recommended every 10 seconds. Maximum gap is 30 seconds before re-attestation triggered.

**Question**: Can I skip integrity verification?
- **Answer**: No. State 0x30 is mandatory. All messages must pass through integrity check.

**Question**: How long is the token in state 0x20?
- **Answer**: Waiting for host `H2T_ECDH_SHARE`. No timeout in protocol (watchdog will timeout after 30s with no activity).

**Question**: What if signature verification fails in state 0x20?
- **Answer**: Send shutdown signal → enter state 0xFF (permanent halt) → restart required.
