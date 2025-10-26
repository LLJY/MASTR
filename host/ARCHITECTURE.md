# MASTR Host Architecture

> **Production-ready** implementation of the MASTR protocol with pluggable crypto backends and comprehensive logging.

---

## 📁 Project Structure

```
host/
├── main.py                  # MASTRHost - Protocol state machine & orchestration
├── logger.py                # Centralized logging with color output
├── crypto_interface.py      # Abstract crypto backend interface (ABC)
├── crypto.py                # NaiveCrypto - File-based implementation
├── protocol.py              # Message type definitions & constants
├── serial_handler.py        # Serial communication with background thread
├── parser.py                # Frame parsing, byte-stuffing, validation
├── ARCHITECTURE.md          # This file
├── README.md                # Getting started guide
└── demos/                   # Interactive tools (if present)
    ├── debug.py             # Manual testing tool
    └── mutual_auth_demo.py  # ECDH demonstration
```

---

## 🏗️ Architecture Overview

### Layer Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    User / Application                        │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  main.py (MASTRHost)                         │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Protocol State Machine                            │     │
│  │  • Phase 0: Key Provisioning                       │     │
│  │  • Phase 1: ECDH Mutual Authentication             │     │
│  │  • Phase 1.5: Channel Verification                 │     │
│  │  • Phase 2: Integrity Verification                 │     │
│  │  • Phase 3: Runtime Heartbeat (TODO)               │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│  Frame Routing: on_frame_received() → _handle_*()           │
└─────────────────────────────────────────────────────────────┘
                              ↓
        ┌──────────────────────────────────────┐
        │                                      │
        ↓                                      ↓
┌─────────────────┐                  ┌─────────────────┐
│   logger.py     │                  │ crypto_interface│
│                 │                  │                 │
│  Logger class   │                  │  CryptoInterface│
│  • success()    │                  │  (ABC)          │
│  • error()      │                  │                 │
│  • info()       │                  │  ┌──────────┐   │
│  • warning()    │                  │  │NaiveCrypto  │
│  • section()    │                  │  │(File-based) │
│  • step()       │                  │  └──────────┘   │
└─────────────────┘                  │                 │
                                     │  ┌──────────┐   │
                                     │  │TPM2Crypto│   │
                                     │  │  (TODO)  │   │
                                     │  └──────────┘   │
                                     └─────────────────┘
                                              ↓
                              ┌───────────────────────────┐
                              │   serial_handler.py       │
                              │                           │
                              │  SerialHandler            │
                              │  • Frame TX with stuffing │
                              │  • Background RX thread   │
                              │  • Auto encryption/decrypt│
                              └───────────────────────────┘
                                              ↓
                              ┌───────────────────────────┐
                              │      parser.py            │
                              │                           │
                              │  FrameParser              │
                              │  • Byte unstuffing        │
                              │  • Frame extraction       │
                              │  • Checksum validation    │
                              └───────────────────────────┘
                                              ↓
                              ┌───────────────────────────┐
                              │   Serial Port (USB CDC)   │
                              │   /dev/ttyACM0 or COM3    │
                              └───────────────────────────┘
                                              ↓
                              ┌───────────────────────────┐
                              │   MASTR Token Device      │
                              │   (RP2040 + ATECC608A)    │
                              └───────────────────────────┘
```

---

## 🔄 Protocol State Machine

### State Transitions

```
┌─────────────────────────────────────────────────────────────┐
│                     INITIALIZATION                           │
└─────────────────────────────────────────────────────────────┘
                              ↓
                    ┌─────────────────┐
                    │  0x00: INIT     │ ← Serial connected
                    └─────────────────┘   Keys loaded
                              ↓
                    Send H2T_ECDH_SHARE
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 1: ECDH HANDSHAKE                   │
└─────────────────────────────────────────────────────────────┘
                              ↓
                    ┌─────────────────┐
                    │ 0x20: ECDH_SENT │
                    └─────────────────┘
                              ↓
                  Receive T2H_ECDH_SHARE
                  Verify signature
                  Compute shared secret
                  Derive session key
                              ↓
                    ┌─────────────────┐
                    │ 0x22: ENCRYPTED │ ← Encryption ENABLED
                    └─────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│               PHASE 1.5: CHANNEL VERIFICATION                │
└─────────────────────────────────────────────────────────────┘
                              ↓
                  Receive encrypted "ping"
                  Send encrypted "pong"
                              ↓
                    ┌─────────────────┐
                    │ 0x24: CHANNEL   │
                    │    ESTABLISHED  │
                    └─────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│              PHASE 2: INTEGRITY VERIFICATION                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
                  Receive T2H_INTEGRITY_CHALLENGE
                  Sign (golden_hash + nonce)
                  Send H2T_INTEGRITY_RESPONSE
                              ↓
                    ┌─────────────────┐
                    │ 0x31: INTEGRITY │
                    │      SENT       │
                    └─────────────────┘
                              ↓
                  Receive T2H_BOOT_OK
                  Send H2T_BOOT_OK_ACK
                              ↓
                    ┌─────────────────┐
                    │ 0x34: COMPLETE  │ ← Ready for operations
                    └─────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│            PHASE 3: RUNTIME HEARTBEAT (TODO)                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
                  Periodic H2T_HEARTBEAT
                  Receive T2H_HEARTBEAT_ACK
                  Monitor for timeout
```

---

## 🔐 Cryptographic Architecture

### Pluggable Backend Design

The crypto layer uses **abstract base class** pattern for maximum flexibility:

```python
# Development: File-based keys
from host.crypto import NaiveCrypto
host = MASTRHost(port="/dev/ttyACM0", crypto=NaiveCrypto())

# Production: TPM2-backed keys (TODO)
from host.crypto_tpm2 import TPM2Crypto
host = MASTRHost(port="/dev/ttyACM0", crypto=TPM2Crypto())
```

### CryptoInterface Methods

All implementations must provide:

| Method | Purpose | Returns |
|--------|---------|---------|
| `load_permanent_keys()` | Load host + token permanent keys | `bool` |
| `generate_permanent_keypair()` | Create new host keypair | `bool` |
| `get_host_permanent_pubkey()` | Get host's public key | `bytes` (64) |
| `set_token_permanent_pubkey()` | Store token's public key | `bool` |
| `generate_ephemeral_keypair()` | Generate P-256 ECDH keypair | `(bytes, object)` |
| `sign_with_permanent_key()` | ECDSA sign with host privkey | `bytes` (64) |
| `verify_signature()` | ECDSA verify with pubkey | `bool` |
| `compute_shared_secret()` | ECDH key agreement | `bytes` (32) |
| `derive_session_key()` | HKDF-SHA256 key derivation | `bytes` (16) |
| `encrypt_payload()` | AES-128-GCM encryption | `bytes` |
| `decrypt_payload()` | AES-128-GCM decryption | `bytes` |
| `should_encrypt()` | Check if encryption enabled | `bool` |

### Encryption Details

**Algorithm:** AES-128-GCM  
**Key Derivation:** HKDF-SHA256  
**HKDF Salt:** `"MASTR-Session-Key-v1"`  
**HKDF Info:** `""` (empty)  
**IV Generation:** `os.urandom(12)` (per message)

**Encrypted Frame Format:**
```
[IV (12 bytes)] [Ciphertext (N bytes)] [Auth Tag (16 bytes)]
```

**Encryption State:**
- **state < 0x22:** Plaintext only
- **state >= 0x22:** All frames encrypted (including DEBUG_MSG)

---

## 📨 Protocol Phases

### Phase 0: Key Provisioning

**Automatic Provisioning** (first-time setup):
```bash
python -m host.main /dev/ttyACM0 --provision
```

**Steps:**
1. Generate host P-256 keypair (ECDSA)
2. Save `host_permanent_privkey.pem` (private key)
3. Save `host_permanent_pubkey.bin` (64 bytes, X||Y)
4. Send host pubkey to token (`H2T_DEBUG_SET_HOST_PUBKEY`)
5. Request token pubkey (`T2H_DEBUG_GET_TOKEN_PUBKEY`)
6. Save `token_permanent_pubkey.bin` (64 bytes, X||Y)
7. Provision default golden hash

**Manual Loading** (subsequent runs):
```bash
python -m host.main /dev/ttyACM0
```
Loads existing keys from disk.

---

### Phase 1: Mutual Authentication (ECDH)

**Goal:** Establish shared secret via authenticated ECDH

```
Host                                    Token
 │                                        │
 │  1. Generate ephemeral P-256 keypair   │
 │     (EH_PrivKey, EH_PubKey)            │
 │                                        │
 │  2. Sign EH_PubKey with H_PrivKey      │
 │     Signature = ECDSA(EH_PubKey)       │
 │                                        │
 │  3. H2T_ECDH_SHARE                     │
 │     [EH_PubKey (64) | Signature (64)]  │
 ├───────────────────────────────────────>│
 │                                        │  4. Verify signature
 │                                        │     using H_PubKey
 │                                        │
 │                                        │  5. Generate ephemeral
 │                                        │     (ET_PrivKey, ET_PubKey)
 │                                        │
 │                                        │  6. Sign ET_PubKey
 │                                        │
 │  7. T2H_ECDH_SHARE                     │
 │     [ET_PubKey (64) | Signature (64)]  │
 │<───────────────────────────────────────┤
 │                                        │
 │  8. Verify signature                   │
 │     using T_PubKey                     │
 │                                        │
 │  9. Compute ECDH                       │  9. Compute ECDH
 │     SharedSecret = ECDH(EH_Priv, ET_Pub)  SharedSecret = ECDH(ET_Priv, EH_Pub)
 │                                        │
 │ 10. Derive session key                 │ 10. Derive session key
 │     SessionKey = HKDF(SharedSecret)    │     SessionKey = HKDF(SharedSecret)
 │                                        │
 │ 11. Enable encryption (state → 0x22)   │ 11. Enable encryption
 │                                        │
```

---

### Phase 1.5: Channel Verification

**Goal:** Confirm both sides have the same session key

```
Host                                    Token
 │                                        │
 │  Wait for encrypted challenge...      │  Generate "ping" challenge
 │                                        │
 │  T2H_CHANNEL_VERIFY_REQUEST (encrypted)│
 │  [IV | Encrypt("ping") | Tag]         │
 │<───────────────────────────────────────┤
 │                                        │
 │  Decrypt with SessionKey               │
 │  Verify payload == "ping"              │
 │                                        │
 │  H2T_CHANNEL_VERIFY_RESPONSE (encrypted)│
 │  [IV | Encrypt("pong") | Tag]         │
 ├───────────────────────────────────────>│
 │                                        │
 │                                        │  Decrypt and verify
 │                                        │  "pong"
 │                                        │
 │  State → 0x24 (ESTABLISHED)            │  State → ESTABLISHED
 │                                        │
```

---

### Phase 2: Integrity Verification

**Goal:** Prove host firmware integrity to token

```
Host                                    Token
 │                                        │
 │  T2H_INTEGRITY_CHALLENGE (encrypted)   │  Generate 4-byte nonce
 │  [IV | Encrypt(nonce) | Tag]          │
 │<───────────────────────────────────────┤
 │                                        │
 │  Decrypt nonce                         │
 │  Load golden_hash from disk            │
 │  Sign (golden_hash || nonce)           │
 │    with H_PrivKey                      │
 │                                        │
 │  H2T_INTEGRITY_RESPONSE (encrypted)    │
 │  [IV | Encrypt(hash||sig) | Tag]      │
 ├───────────────────────────────────────>│
 │                                        │
 │                                        │  Decrypt
 │                                        │  Verify signature
 │                                        │  Compare hash
 │                                        │
 │  T2H_BOOT_OK (encrypted)               │  If valid:
 │<───────────────────────────────────────┤  Send BOOT_OK
 │                                        │
 │  H2T_BOOT_OK_ACK (encrypted)           │
 ├───────────────────────────────────────>│
 │                                        │
 │  State → 0x34 (COMPLETE)               │  State → COMPLETE
 │                                        │
```

---

### Phase 3: Runtime Heartbeat (TODO)

**Goal:** Detect disconnection and tampering

**Planned Implementation:**
- Host sends `H2T_HEARTBEAT` every 5 seconds
- Token responds with `T2H_HEARTBEAT_ACK`
- If 3 consecutive heartbeats timeout → shutdown both sides
- Encrypted heartbeats prevent replay attacks

---

## 🎯 Core Components

### 1. MASTRHost (main.py)

**Responsibilities:**
- Protocol state machine orchestration
- Frame routing to handlers
- Synchronization with threading events
- Crypto backend management

**Key Methods:**

| Method | Purpose | Returns |
|--------|---------|---------|
| `run()` | Main execution loop | `int` (exit code) |
| `on_frame_received()` | Route frames to handlers | `None` |
| `_handle_*()` | Process specific message types | `None` |
| `_load_or_generate_keys()` | Phase 0 implementation | `bool` |
| `_perform_ecdh_handshake()` | Phase 1 implementation | `bool` |
| `_perform_channel_verification()` | Phase 1.5 implementation | `bool` |
| `_perform_integrity_verification()` | Phase 2 implementation | `bool` |

---

### 2. Logger (logger.py)

**Centralized logging** with consistent color-coded output.

**Methods:**

```python
Logger.success("Operation completed")           # Green ✓
Logger.error("Operation failed")                # Red ✗
Logger.info("Information message")              # Cyan [INFO]
Logger.warning("Warning message")               # Yellow [WARNING]
Logger.debug("TOKEN", "Debug message")          # Orange [TOKEN]
Logger.section("Phase 1: Authentication")       # Cyan header
Logger.step(1, "Generating keypair...")         # Numbered step
Logger.substep("Details...")                    # Indented info
```

**Benefits:**
- ~150 lines of code reduction
- Consistent formatting
- Easy to disable colors or redirect output
- Single point of control

---

### 3. SerialHandler (serial_handler.py)

**Responsibilities:**
- Background thread for continuous reading
- Frame transmission with byte-stuffing
- Automatic encryption/decryption
- Connection management

**Key Features:**
- Non-blocking serial I/O
- Automatic reconnection support
- Callback-based frame delivery
- Transparent crypto layer integration

---

### 4. FrameParser (parser.py)

**Responsibilities:**
- Byte-unstuffing (`0x7D` escape sequences)
- Frame boundary detection (`0x7F` SOF, `0x7E` EOF)
- Checksum validation

**Stateful Parsing:**
```
Raw bytes → Unstuff → Extract frames → Validate → Deliver
```

---

## 🔧 Development Guide

### Adding a New Message Type

**1. Define in protocol.py:**
```python
class MessageType(IntEnum):
    H2T_MY_NEW_REQUEST = 0x50
    T2H_MY_NEW_RESPONSE = 0x51
```

**2. Add handler in main.py:**
```python
def _handle_my_new_response(self, payload: bytes) -> None:
    """Handle T2H_MY_NEW_RESPONSE"""
    Logger.info(f"Received response: {payload.hex()}")
    # Process payload...
```

**3. Register in on_frame_received():**
```python
elif frame.msg_type == MessageType.T2H_MY_NEW_RESPONSE:
    self._handle_my_new_response(payload)
```

**4. Implement C-side in src/protocol.c:**
```c
case H2T_MY_NEW_REQUEST:
    // Generate response
    send_message(T2H_MY_NEW_RESPONSE, data, len);
    break;
```

---

### Creating a New Crypto Backend

**1. Implement CryptoInterface:**
```python
from host.crypto_interface import CryptoInterface

class TPM2Crypto(CryptoInterface):
    def __init__(self) -> None:
        super().__init__()
        # Initialize TPM2 context
    
    def load_permanent_keys(self) -> bool:
        # Load from TPM2 NVRAM
        pass
    
    def sign_with_permanent_key(self, message: bytes) -> Optional[bytes]:
        # Use TPM2_Sign
        pass
    
    # ... implement all abstract methods
```

**2. Add to CLI options in main():**
```python
parser.add_argument('--crypto', choices=['naive', 'tpm2'])
```

**3. Instantiate based on argument:**
```python
if args.crypto == 'tpm2':
    crypto = TPM2Crypto()
```

**Done!** No changes to protocol code needed.

---

## 📊 Message Flow Example

### Successful Authentication Flow

```
Time  Host                          Token
═══════════════════════════════════════════════════════════

t0    Connect serial port           ← Power on
      Load keys
      
t1    H2T_ECDH_SHARE    ──────────> Verify signature
      (EH_Pub + Sig)                Generate ET keypair
                                    Sign ET_Pub
      
t2    T2H_ECDH_SHARE    <────────── Send share
      Verify signature              (ET_Pub + Sig)
      Compute shared secret
      Derive session key
      Enable encryption
      
t3    T2H_CHANNEL_VERIFY_REQUEST   Generate ping
      Decrypt "ping"    <────────── Encrypt & send
      
t4    H2T_CHANNEL_VERIFY_RESPONSE  Decrypt "pong"
      Encrypt "pong"    ──────────> Verify match
      
t5                                  Generate nonce
      T2H_INTEGRITY_CHALLENGE
      Decrypt nonce     <────────── Encrypt & send
      
t6    Load golden hash
      Sign (hash||nonce)
      H2T_INTEGRITY_RESPONSE
      Encrypt & send    ──────────> Decrypt
                                    Verify signature
                                    Compare hash
                                    
t7    T2H_BOOT_OK       <────────── If valid:
      Decrypt           <────────── send BOOT_OK
      
t8    H2T_BOOT_OK_ACK   ──────────> Receive ACK
      Send ACK
      
t9    ✅ READY FOR OPERATIONS ✅
```

---

## 🧪 Testing

### Quick Test
```bash
# With existing keys
python -m host.main /dev/ttyACM0

# Verbose output
python -m host.main /dev/ttyACM0 -v
```

### First-Time Setup
```bash
# Auto-provision everything
python -m host.main /dev/ttyACM0 --provision
```

### Custom Crypto Backend
```bash
# Use TPM2 (when implemented)
python -m host.main /dev/ttyACM0 --crypto=tpm2
```

---

## 📝 Recent Improvements

### Phase 1 Code Cleanup (Completed)

1. ✅ **Centralized Logging** - Created `Logger` class
2. ✅ **Type Hints** - Added return types to all methods
3. ✅ **Removed Debug Output** - Cleaned crypto.py
4. ✅ **Consistent Formatting** - Professional output

**Impact:**
- ~150 lines removed
- Better readability
- Easier maintenance
- Professional appearance

---

## 🎯 Future Work

- [ ] **Phase 3:** Runtime heartbeat implementation
- [ ] **TPM2Crypto:** Hardware-backed key storage
- [ ] **Error Recovery:** Auto-reconnection logic
- [ ] **Session Resumption:** Resume from last state
- [ ] **Metrics:** Performance monitoring
- [ ] **Testing:** Unit tests for all phases

---

## 📚 See Also

- **README.md** - Quick start guide
- **protocol.py** - Message type reference
- **Protocol diagrams** - See docs/ folder
- **C implementation** - See src/ folder

---

**Last Updated:** 2024-10-26  
**Version:** 2.0 (Post Phase 1 Cleanup)
