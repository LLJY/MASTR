# MASTR Protocol Specification

## 1. Overview
The MASTR (Mutual Attested Secure Token for Robotics) protocol establishes a secure, authenticated channel between a Host (e.g., initramfs) and a Hardware Token (Raspberry Pi Pico + ATECC608A). Its primary purpose is to act as an **Integrity Gate**, ensuring the host firmware has not been tampered with before allowing the boot process to proceed and triggering immediate shutdown upon periodic re-attestation checking failures.

## 2. Cryptographic Primitives
The protocol relies on the following primitives, backed by the ATECC608A hardware security module where possible:

*   **Asymmetric Keypair**: NIST P-256 (SECP256R1).
*   **Key Exchange**: ECDH (Elliptic Curve Diffie-Hellman) over P-256.
*   **Signatures**: ECDSA (P-256) with SHA-256.
    *   *Note*: Signatures on the wire are **Raw R||S** (64 bytes), not DER encoded.
*   **Hashing**: SHA-256.
*   **KDF**: HKDF-SHA256.
    *   Salt: `b"MASTR-Session-Key-v1"`
    *   Info: `b""`
*   **Symmetric Encryption**: AES-128-GCM.
    *   IV: 12 bytes (Random).
    *   Tag: 16 bytes.
    *   Key: 16 bytes (Derived via HKDF).

## 3. Protocol State Machine
The Token enforces a strict linear state machine. Out-of-order messages trigger an error or immediate shutdown.

| State ID | Name | Description | Allowed Transitions |
| :--- | :--- | :--- | :--- |
| `0x00` | `INITIAL` | Power-on state. | -> `0x20` (Auto) |
| `0x10` | `UNPROVISIONED` | Keys/Hash missing. | -> `0x20` (On Provision) |
| `0x20` | `WAIT_ECDH` | Waiting for Host's ECDH Share. | -> `0x21` (On Valid Share) |
| `0x21` | `ECDH_DONE` | ECDH Complete / Waiting for Host Share (Re-attest). | -> `0x22` (Initial) / `0x22` (Re-attest) |
| `0x22` | `CHANNEL_VERIFY` | Waiting for Encrypted Pong. | -> `0x30` (On Valid Pong) |
| `0x30` | `INTEGRITY_VERIFY` | Waiting for Integrity Response. | -> `0x32` (On Valid Sig + Hash) |
| `0x32` | `BOOT_OK_SENT` | BOOT_OK sent, waiting for ACK. | -> `0x40` (On ACK) |
| `0x40` | `RUNTIME` | Session Established. Heartbeats active. | -> `0x21` (On Re-attest) |
| `0xFF` | `HALT` | Security Violation. Permanent Halt. | None (Requires Reset) |

## 4. Protocol Phases

### Phase 0: Provisioning (Pre-requisite)
Before the protocol can run, the Token and Host must be provisioned:
1.  **Host Pubkey**: Stored in Token Slot 8 (Data Zone, Block 0-1).
2.  **Token Pubkey**: Stored in Host filesystem (`token_permanent_pubkey.bin`).
3.  **Golden Hash**: Expected SHA-256 hash of Host firmware, stored in Token Slot 8 (Data Zone, Block 2).

### Phase 1: Mutual Authentication (ECDH)
**State: `0x20`**
1.  **Host** generates Ephemeral Keypair ($E_H$).
2.  **Host** signs $E_H$ public key with Permanent Key ($P_H$).
3.  **Host** sends `H2T_ECDH_SHARE` ($E_H || Sig_H$).
4.  **Token** verifies $Sig_H$ using stored $P_H$.
5.  **Token** generates Ephemeral Keypair ($E_T$).
6.  **Token** computes Shared Secret ($S = ECDH(E_T, E_H)$).
7.  **Token** derives Session Key ($K_{sess} = HKDF(S)$).
8.  **Token** signs $E_T$ with Permanent Key ($P_T$).
9.  **Token** sends `T2H_ECDH_SHARE` ($E_T || Sig_T$).
10. **Host** verifies $Sig_T$, computes $S$, derives $K_{sess}$.

### Phase 1.5: Channel Verification
**State: `0x22`**
*Encryption is enabled for all subsequent messages.*
1.  **Token** waits 1 second (processing delay).
2.  **Token** sends `T2H_CHANNEL_VERIFY_REQUEST` (Payload: `"ping"`).
3.  **Host** decrypts, verifies `"ping"`.
4.  **Host** sends `H2T_CHANNEL_VERIFY_RESPONSE` (Payload: `"pong"`).
5.  **Token** decrypts, verifies `"pong"`.

### Phase 2: Integrity Verification
**State: `0x30`**
1.  **Token** generates random 4-byte `Nonce`.
2.  **Token** sends `T2H_INTEGRITY_CHALLENGE` (`Nonce`).
3.  **Host** loads `GoldenHash` (from file/memory).
4.  **Host** signs (`GoldenHash` || `Nonce`) with $P_H$.
5.  **Host** sends `H2T_INTEGRITY_RESPONSE` (`GoldenHash` || `Sig`).
6.  **Token** verifies `Sig` over (`GoldenHash` || `Nonce`). **(CRITICAL: Checked FIRST)**
7.  **Token** compares received `GoldenHash` with stored `GoldenHash`.
8.  If both pass:
    *   **Token** sends `T2H_BOOT_OK`.
    *   State -> `0x32`.
9.  If either fails:
    *   **Token** enters `HALT` state (`0xFF`).
    *   **Token** spams `T2H_INTEGRITY_FAIL_HALT` indefinitely.

### Phase 3: Boot & Runtime
**State: `0x32` -> `0x40`**
1.  **Host** receives `BOOT_OK`, allows boot process to continue.
2.  **Host** sends `H2T_BOOT_OK_ACK`.
3.  **Token** enters `RUNTIME` state (`0x40`).
4.  **Token** starts session timer (30s default).
5.  **Host** must send `H2T_HEARTBEAT` periodically to keep session alive.
6.  **Token** responds with `T2H_HEARTBEAT_ACK`.

### Phase 4: Runtime Re-attestation
**State: `0x40` -> `0x21`**
If the session times out, the Token triggers a re-attestation cycle to rotate the session key.
1.  **Token** invalidates current session (but keeps old key for encryption).
2.  **Token** generates new Ephemeral Keypair ($E'_T$).
3.  **Token** sends `T2H_ECDH_SHARE` ($E'_T || Sig'_T$).
4.  **Token** sets state to `0x21` (Waiting for Host Share).
5.  **Host** receives `T2H_ECDH_SHARE`, verifies signature.
6.  **Host** generates new Ephemeral Keypair ($E'_H$).
7.  **Host** sends `H2T_ECDH_SHARE` ($E'_H || Sig'_H$).
8.  **Host** immediately switches to new session key.
9.  **Token** receives `H2T_ECDH_SHARE`, verifies signature.
10. **Token** derives new session key and switches.
11. Protocol continues from **Phase 1.5** (Channel Verify).

## 5. Message Format

### Wire Format
The protocol uses a byte-stuffed serial frame format with Start/End markers.

**Structure:**
`[SOF] [Stuffed Data] [EOF]`

*   **SOF** (Start of Frame): `0x7F`
*   **EOF** (End of Frame): `0x7E`
*   **ESC** (Escape Byte): `0x7D`

**Stuffed Data Content (Before Stuffing):**
| Field | Length | Description |
| :--- | :--- | :--- |
| `Type` | 1 byte | Message Type ID |
| `Len` | 2 bytes | Length of Payload (Big Endian) |
| `Payload` | N bytes | Message Data |
| `Checksum`| 1 byte | Rolling 8-bit sum of Type + Len + Payload |

### Message Type IDs
| ID | Name | Description |
| :--- | :--- | :--- |
| `0x00` | `T2H_ERROR` | Generic Error |
| `0x01` | `T2H_NACK` | Negative Acknowledgement |
| `0x20` | `H2T_ECDH_SHARE` | Host ECDH Share |
| `0x21` | `T2H_ECDH_SHARE` | Token ECDH Share |
| `0x22` | `T2H_CHANNEL_VERIFY_REQUEST` | Encrypted Ping Challenge |
| `0x23` | `H2T_CHANNEL_VERIFY_RESPONSE` | Encrypted Pong Response |
| `0x30` | `T2H_INTEGRITY_CHALLENGE` | Integrity Challenge (Nonce) |
| `0x31` | `H2T_INTEGRITY_RESPONSE` | Integrity Response (Hash + Sig) |
| `0x32` | `T2H_BOOT_OK` | Boot Authorized |
| `0x33` | `T2H_INTEGRITY_FAIL_HALT` | Integrity Failure (Halt) |
| `0x34` | `H2T_BOOT_OK_ACK` | Boot OK Acknowledgement |
| `0x40` | `H2T_HEARTBEAT` | Runtime Heartbeat |
| `0x41` | `T2H_HEARTBEAT_ACK` | Heartbeat Acknowledgement |

**Byte Stuffing Rules:**
*   If `SOF`, `EOF`, or `ESC` appear in the data, they are escaped:
    *   `0x7F` -> `0x7D 0x5F`
    *   `0x7E` -> `0x7D 0x5E`
    *   `0x7D` -> `0x7D 0x5D`

### Encryption Format (AES-GCM)
When encryption is enabled, the **entire inner frame** (Type + Len + Payload + Checksum) is encrypted. The wire format becomes:

`[SOF] [Stuffed( IV || Ciphertext || Tag )] [EOF]`

*   **IV**: 12 bytes
*   **Ciphertext**: Encrypted (Type + Len + Payload + Checksum)
*   **Tag**: 16 bytes (Auth Tag)

## 6. Security Features

### Panic on Debug
If the Host receives a `DEBUG_MSG` frame from the Token while not in explicit debug mode, the Host MUST immediately panic (exit with error). This prevents a compromised Token from leaking internal state or confusing the Host logs.

### Halt Spam
Upon a critical security failure (Integrity Check fail, Signature fail), the Token enters a `HALT` state (`0xFF`) and continuously sends `T2H_INTEGRITY_FAIL_HALT` messages. This ensures the Host cannot ignore the failure and proceed with boot. The only recovery is a hard reset of the Token AND THE HOST.

### Session Timeout
In `RUNTIME` state, if no heartbeat is received within the timeout period (30s), the Token invalidates the session and requires a full re-attestation (Phase 1) to resume.
