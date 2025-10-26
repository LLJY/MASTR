# MASTR Host Architecture

## Overview

The MASTR host implementation follows a clean, modular architecture with pluggable cryptographic backends and a clear protocol state machine.

## Project Structure

```
host/
├── main.py                  # Production protocol implementation
├── crypto_interface.py      # Abstract crypto backend interface
├── crypto.py                # NaiveCrypto (file-based) implementation
├── protocol.py              # Message type definitions
├── serial_handler.py        # Serial communication layer
├── parser.py                # Frame parsing and validation
├── demos/
│   ├── debug.py            # Interactive debugger
│   └── mutual_auth_demo.py # ECDH demo
└── ARCHITECTURE.md         # This file
```

## Core Components

### 1. `main.py` - Protocol State Machine

The main protocol implementation (`MASTRHost` class) manages:
- Serial communication lifecycle
- Protocol state transitions (0x00 → 0x20 → 0x21 → 0x22 → 0x24)
- Frame routing and handling
- ECDH handshake execution
- Channel verification

**Key Methods:**
- `run()` - Main execution loop
- `_perform_ecdh_handshake()` - Phase 1 implementation
- `_perform_channel_verification()` - Channel verification
- `on_frame_received()` - Frame dispatcher
- `_handle_*()` - Individual message handlers

### 2. Crypto Architecture

#### Pluggable Design

All cryptographic operations go through the `CryptoInterface` abstract base class. This allows switching between implementations without changing protocol code.

```python
# Use file-based crypto (development)
host = MASTRHost(port, crypto=NaiveCrypto())

# Use TPM2 crypto (production) - TODO
host = MASTRHost(port, crypto=TPM2Crypto())
```

#### Current Implementations

**NaiveCrypto** (`crypto.py`):
- File-based key storage (PEM/binary files)
- Uses Python `cryptography` library
- Suitable for development and testing
- **NOT for production** (private keys on disk)

**TPM2Crypto** (TODO):
- TPM2-based secure key storage
- Hardware-backed operations
- Production-ready security

#### CryptoInterface Methods

All implementations must provide:
- `load_permanent_keys()` - Load host/token keypairs
- `generate_ephemeral_keypair()` - P-256 ECDH keypair
- `sign_with_permanent_key()` - ECDSA signature
- `verify_signature()` - ECDSA verification
- `compute_shared_secret()` - ECDH operation
- `derive_session_key()` - HKDF-SHA256 key derivation
- `encrypt_payload()` - AES-128-GCM encryption
- `decrypt_payload()` - AES-128-GCM decryption
- `should_encrypt()` - State-based encryption decision

### 3. Protocol Layers

```
┌─────────────────────────────────────┐
│         main.py (MASTRHost)         │  ← Protocol logic
│   - State machine                   │
│   - ECDH handshake                  │
│   - Channel verification            │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│      crypto_interface.py            │  ← Crypto abstraction
│   - Pluggable backend               │
│   - crypto.py (NaiveCrypto)         │
│   - [TPM2Crypto] (TODO)             │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│     serial_handler.py               │  ← Communication layer
│   - Frame transmission              │
│   - Byte stuffing                   │
│   - Background reading              │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│        parser.py                    │  ← Frame parsing
│   - Unstuffing                      │
│   - Checksum validation             │
│   - Frame extraction                │
└─────────────────────────────────────┘
```

## Protocol Flow

### Phase 0: Key Provisioning
1. Load host permanent keypair (or generate if missing)
2. Load token permanent pubkey (or request via `--provision`)
3. Verify keys are valid

### Phase 1: Mutual Authentication (ECDH)
1. Generate ephemeral P-256 keypair
2. Sign ephemeral pubkey with permanent privkey
3. Send `H2T_ECDH_SHARE` (ephemeral pubkey + signature)
4. Receive `T2H_ECDH_SHARE` (token's ephemeral pubkey + signature)
5. Verify token's signature using token's permanent pubkey
6. Compute ECDH shared secret
7. Derive AES-128 session key via HKDF-SHA256

### Phase 1.5: Channel Verification
1. Receive encrypted "ping" challenge (`T2H_CHANNEL_VERIFY_REQUEST`)
2. Decrypt and verify
3. Send encrypted "pong" response (`H2T_CHANNEL_VERIFY_RESPONSE`)
4. Protocol state → 0x24 (established)

### Phase 2: Integrity Verification (TODO)
- Token challenges host firmware integrity
- Host provides signed attestation
- Token validates before allowing operations

### Phase 3: Runtime Heartbeat (TODO)
- Periodic keep-alive messages
- Detect disconnection or tampering
- Automatic session teardown on timeout

## Encryption Behavior

**Before Channel Establishment (state < 0x22):**
- All messages sent in plaintext
- No encryption overhead

**After Channel Establishment (state >= 0x22):**
- ALL messages encrypted (including debug)
- AES-128-GCM with random IV per message
- Format: `[IV(12)][Ciphertext(N)][Tag(16)]`
- Decryption happens in `on_frame_received()` before routing

## Extending the Protocol

### Adding a New Message Type

1. **Define message type in `protocol.py`:**
```python
class MessageType(IntEnum):
    H2T_NEW_MESSAGE = 0x50
    T2H_NEW_RESPONSE = 0x51
```

2. **Add handler to `MASTRHost`:**
```python
def _handle_new_message(self, payload: bytes):
    """Handle T2H_NEW_RESPONSE"""
    # Process payload
    pass
```

3. **Register in `on_frame_received()`:**
```python
elif frame.msg_type == MessageType.T2H_NEW_RESPONSE:
    self._handle_new_message(payload)
```

4. **Implement C-side handler in `src/protocol.c`:**
```c
case H2T_NEW_MESSAGE:
    // Handle message
    send_message(T2H_NEW_RESPONSE, response_data, len);
    break;
```

### Adding a New Crypto Backend

1. **Create new class implementing `CryptoInterface`:**
```python
from .crypto_interface import CryptoInterface

class TPM2Crypto(CryptoInterface):
    def load_permanent_keys(self) -> bool:
        # TPM2 implementation
        pass
    # ... implement all methods
```

2. **Add to command-line options:**
```python
parser.add_argument('--crypto', choices=['naive', 'tpm2', 'mynew'])
```

3. **Instantiate in `main()`:**
```python
elif args.crypto == 'mynew':
    crypto = MyNewCrypto()
```

That's it! The protocol code doesn't need to change.

## State Machine

```
0x00 (INIT) 
  ↓ H2T_ECDH_SHARE sent
0x20 (ECDH_SENT)
  ↓ T2H_ECDH_SHARE received, verified
0x21 (ECDH_COMPLETE)
  ↓ T2H_CHANNEL_VERIFY_REQUEST received
0x22 (CHANNEL_VERIFY) ← Encryption enabled
  ↓ H2T_CHANNEL_VERIFY_RESPONSE sent
0x24 (ESTABLISHED)
  ↓ Ready for operations
```

## Testing

**Quick Test (with existing keys):**
```bash
python -m host.main /dev/ttyACM0
```

**Auto-provision new keys:**
```bash
python -m host.main /dev/ttyACM0 --provision
```

**Verbose mode:**
```bash
python -m host.main /dev/ttyACM0 -v
```

**Interactive debugging:**
```bash
python -m host.demos.debug /dev/ttyACM0
```

**ECDH demonstration:**
```bash
python -m host.demos.mutual_auth_demo /dev/ttyACM0
```

## Key Files

**Generated by provisioning:**
- `host_permanent_privkey.pem` - Host's ECDSA private key (PEM)
- `host_permanent_pubkey.bin` - Host's public key (64 bytes raw)
- `token_permanent_pubkey.bin` - Token's public key (64 bytes raw)

**Security Note:** The naive implementation stores keys in plaintext files. For production, use TPM2 backend.

## Future Work

- [ ] Implement Phase 2: Integrity Verification
- [ ] Implement Phase 3: Runtime Heartbeat
- [ ] Implement TPM2Crypto backend
- [ ] Add automatic reconnection logic
- [ ] Add session resumption support
- [ ] Add comprehensive error recovery
