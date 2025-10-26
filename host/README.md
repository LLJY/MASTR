# MASTR Host - Python Implementation

> **Production-ready** Python host for MASTR protocol communication with hardware security tokens.

[![Protocol](https://img.shields.io/badge/Protocol-MASTR-blue)](../docs/)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Active-success)]()

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Protocol Phases](#-protocol-phases)
- [Architecture](#-architecture)
- [Development](#-development)
- [Troubleshooting](#-troubleshooting)

---

## 🎯 Overview

The MASTR Host implements a secure communication protocol between a host computer and a hardware security token (RP2040 + ATECC608A). It provides:

### **Features**
✅ **Mutual Authentication** via ECDH key exchange  
✅ **AES-128-GCM Encryption** for all communications  
✅ **Integrity Verification** with cryptographic attestation  
✅ **Pluggable Crypto Backends** (File-based or TPM2)  
✅ **Automatic Key Provisioning** for first-time setup  
✅ **Clean Logging** with color-coded output  
✅ **Type-Safe** with comprehensive type hints  

### **Security Guarantee**
- Permanent keys use **P-256 ECDSA**
- Session keys derived via **HKDF-SHA256**
- All data encrypted with **AES-128-GCM**
- Hardware RNG for IV generation
- Firmware integrity attestation

---

## 🚀 Quick Start

### First-Time Setup (Automatic Provisioning)

```bash
# 1. Connect your MASTR token via USB
# 2. Run with --provision flag
python -m host.main /dev/ttyACM0 --provision

# This will:
#   ✓ Generate host keypair
#   ✓ Exchange keys with token
#   ✓ Set up golden hash for integrity checks
#   ✓ Perform full authentication
```

**Output:**
```
============================================================
MASTR Host - Production Protocol Implementation
============================================================
Port: /dev/ttyACM0
Crypto: NaiveCrypto

=== Connecting to Token ===
✓ Connected to /dev/ttyACM0

=== Phase 0: Key Loading ===
[INFO] Provision mode: Regenerating keypair...
✓ Generated new host keypair

=== Auto-Provisioning Token Key ===
...
✓ Keys provisioned successfully!

=== Phase 1: Mutual Authentication (ECDH) ===
...
✓ Session key: c8c2f188ffa06388c56ed44454b6309a

=== Channel Verification ===
...
✓ Pong sent

============================================================
✅ Secure channel established!
============================================================

=== Phase 2: Integrity Verification ===
...
✓ Token sent BOOT_OK - integrity verification passed!

============================================================
✅ Integrity verification complete!
============================================================
```

### Subsequent Runs (With Existing Keys)

```bash
# Just run normally - keys are loaded from disk
python -m host.main /dev/ttyACM0
```

---

## 📦 Installation

### Prerequisites

- **Python 3.8+**
- **pySerial** for serial communication
- **cryptography** library for crypto operations

### Install Dependencies

```bash
# From project root
cd host/
pip install -r requirements.txt
```

**Or manually:**
```bash
pip install pyserial cryptography
```

### Platform-Specific Notes

**Linux:**
```bash
# Add user to dialout group for serial access
sudo usermod -a -G dialout $USER
# Log out and back in for changes to take effect
```

**macOS:**
```bash
# No special setup needed
# Devices appear as /dev/tty.usbmodemXXXX
```

**Windows:**
```bash
# Devices appear as COM3, COM4, etc.
# No special setup needed
```

---

## 💻 Usage

### Command-Line Interface

```bash
python -m host.main <port> [options]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `port` | Serial port (e.g., /dev/ttyACM0, COM3) | *Required* |
| `-b, --baudrate` | Baud rate | 115200 |
| `-v, --verbose` | Enable verbose output | False |
| `--crypto` | Crypto backend: `naive` or `tpm2` | `naive` |
| `--provision` | Auto-provision keys and golden hash | False |

### Examples

**Basic usage:**
```bash
python -m host.main /dev/ttyACM0
```

**Verbose mode:**
```bash
python -m host.main /dev/ttyACM0 -v
```

**Different baud rate:**
```bash
python -m host.main /dev/ttyACM0 -b 9600
```

**Windows:**
```bash
python -m host.main COM3
```

**With TPM2 backend (when implemented):**
```bash
python -m host.main /dev/ttyACM0 --crypto=tpm2
```

---

## 🔄 Protocol Phases

### Phase 0: Key Provisioning

**Automatic** (with `--provision`):
```bash
python -m host.main /dev/ttyACM0 --provision
```

**Generates:**
- `host_permanent_privkey.pem` - Host's private key (ECDSA, keep secret!)
- `host_permanent_pubkey.bin` - Host's public key (64 bytes, X||Y)
- `token_permanent_pubkey.bin` - Token's public key (64 bytes, X||Y)
- `golden_hash.bin` - Expected firmware hash (32 bytes, SHA-256)

**Manual** (existing keys):
```bash
python -m host.main /dev/ttyACM0
```
Loads keys from disk automatically.

---

### Phase 1: Mutual Authentication (ECDH)

**What happens:**
1. Host generates ephemeral P-256 keypair
2. Host signs ephemeral pubkey with permanent key
3. Host sends `H2T_ECDH_SHARE` (pubkey + signature)
4. Token verifies signature, generates its own ephemeral keypair
5. Token sends `T2H_ECDH_SHARE` (pubkey + signature)
6. Both sides compute ECDH shared secret
7. Both sides derive AES-128 session key via HKDF-SHA256
8. **Encryption enabled** (state → 0x22)

**Security:**
- Mutual authentication prevents MITM attacks
- Ephemeral keys provide forward secrecy
- ECDSA signatures ensure authenticity

---

### Phase 1.5: Channel Verification

**What happens:**
1. Token sends encrypted "ping" challenge
2. Host decrypts and verifies
3. Host sends encrypted "pong" response
4. Token verifies response
5. **Channel established** (state → 0x24)

**Purpose:**
- Confirms both sides have same session key
- Detects key derivation errors
- Required before integrity verification

---

### Phase 2: Integrity Verification

**What happens:**
1. Token sends 4-byte random nonce (encrypted)
2. Host loads golden hash from disk
3. Host signs `(golden_hash || nonce)` with permanent key
4. Host sends `H2T_INTEGRITY_RESPONSE` (hash + signature, encrypted)
5. Token verifies signature and compares hash
6. If valid: Token sends `T2H_BOOT_OK` (encrypted)
7. Host acknowledges with `H2T_BOOT_OK_ACK`
8. **Ready for operations** (state → 0x34)

**Purpose:**
- Proves host firmware integrity
- Prevents unauthorized/modified hosts
- Token enforces this before allowing operations

---

### Phase 3: Runtime Heartbeat (TODO)

**Planned:**
- Periodic encrypted heartbeats every 5 seconds
- Detects disconnection or tampering
- Automatic shutdown on timeout

---

## 🏗️ Architecture

### File Structure

```
host/
├── main.py                  # MASTRHost class - state machine
├── logger.py                # Centralized logging
├── crypto_interface.py      # Abstract crypto interface
├── crypto.py                # NaiveCrypto implementation
├── protocol.py              # Message type definitions
├── serial_handler.py        # Serial communication
├── parser.py                # Frame parsing
├── ARCHITECTURE.md          # Detailed architecture docs
└── README.md                # This file
```

### Component Diagram

```
┌──────────────┐
│ main.py      │ ← Protocol state machine
│ (MASTRHost)  │   Frame routing
└──────┬───────┘
       │
   ┌───┴────────────────┐
   │                    │
┌──▼───────┐     ┌──────▼──────┐
│logger.py │     │crypto_      │
│          │     │interface.py │
│Logger    │     │             │
│methods   │     │NaiveCrypto  │
└──────────┘     │TPM2Crypto   │
                 └──────┬──────┘
                        │
                 ┌──────▼──────┐
                 │serial_      │
                 │handler.py   │
                 │             │
                 │Background   │
                 │RX thread    │
                 └──────┬──────┘
                        │
                 ┌──────▼──────┐
                 │parser.py    │
                 │             │
                 │Frame        │
                 │extraction   │
                 └──────┬──────┘
                        │
                        ▼
                  Serial Port
```

### Data Flow

```
User Command
    │
    ├──> MASTRHost.run()
    │        │
    │        ├──> Load/Generate Keys (Phase 0)
    │        │        │
    │        │        └──> CryptoInterface methods
    │        │
    │        ├──> ECDH Handshake (Phase 1)
    │        │        │
    │        │        ├──> SerialHandler.send_frame()
    │        │        │        │
    │        │        │        └──> Byte stuffing
    │        │        │             Encryption
    │        │        │             Serial TX
    │        │        │
    │        │        └──> Wait for response
    │        │                 │
    │        │                 └──> FrameParser
    │        │                      on_frame_received()
    │        │                      Route to handler
    │        │
    │        ├──> Channel Verify (Phase 1.5)
    │        │
    │        └──> Integrity Verify (Phase 2)
    │
    └──> Keep connection open
```

---

## 🛠️ Development

### Project Setup

```bash
# Clone repository
git clone <repo-url>
cd MASTR-NEW/host/

# Install dependencies
pip install -r requirements.txt

# Run tests (if available)
python -m pytest
```

### Adding a New Message Type

**1. Define in [`protocol.py`](protocol.py):**
```python
class MessageType(IntEnum):
    H2T_MY_REQUEST = 0x60
    T2H_MY_RESPONSE = 0x61
```

**2. Add handler in [`main.py`](main.py):**
```python
def _handle_my_response(self, payload: bytes) -> None:
    """Handle T2H_MY_RESPONSE"""
    Logger.info(f"Got response: {payload.hex()}")
    # Process...
```

**3. Register in `on_frame_received()`:**
```python
elif frame.msg_type == MessageType.T2H_MY_RESPONSE:
    self._handle_my_response(payload)
```

**4. Implement token-side in C:**
```c
// In src/protocol.c
case H2T_MY_REQUEST:
    // Handle request
    send_message(T2H_MY_RESPONSE, data, len);
    break;
```

### Creating a Custom Crypto Backend

**1. Implement [`CryptoInterface`](crypto_interface.py):**
```python
from host.crypto_interface import CryptoInterface

class MyCustomCrypto(CryptoInterface):
    def __init__(self) -> None:
        super().__init__()
        # Your initialization
    
    def load_permanent_keys(self) -> bool:
        # Your implementation
        pass
    
    # ... implement all abstract methods
```

**2. Use your backend:**
```python
from host.crypto_mycustom import MyCustomCrypto

host = MASTRHost(
    port="/dev/ttyACM0",
    crypto=MyCustomCrypto()
)
```

### Using the Logger

```python
from host.logger import Logger

# Success messages (green checkmark)
Logger.success("Operation completed")

# Errors (red X)
Logger.error("Operation failed")

# Info (cyan)
Logger.info("Processing...")

# Warnings (yellow)
Logger.warning("Deprecated feature")

# Debug (orange)
Logger.debug("TAG", "Debug message")

# Sections (cyan header)
Logger.section("Phase 1: Authentication")

# Steps (numbered)
Logger.step(1, "Generating keypair...")
Logger.substep("Details about this step...")
```

---

## 🔍 Troubleshooting

### Common Issues

#### "Failed to connect to /dev/ttyACM0"

**Causes:**
- Device not plugged in
- Wrong port name
- Permission denied (Linux)

**Solutions:**
```bash
# Linux: Check devices
ls -l /dev/ttyACM*
ls -l /dev/ttyUSB*

# Add user to dialout group
sudo usermod -a -G dialout $USER
# Log out and back in

# macOS: Check devices
ls -l /dev/tty.usbmodem*

# Windows: Check Device Manager
# Look under "Ports (COM & LPT)"
```

#### "Permanent keys not found"

**Cause:** First-time run without `--provision`

**Solution:**
```bash
python -m host.main /dev/ttyACM0 --provision
```

#### "Timeout waiting for T2H_ECDH_SHARE"

**Causes:**
- Token not responding
- Token firmware issue
- Wrong baud rate

**Solutions:**
```bash
# Reset token (unplug/replug)
# Try different baud rate
python -m host.main /dev/ttyACM0 -b 9600

# Check token is running correct firmware
```

#### "Signature verification failed"

**Causes:**
- Mismatched keys between host and token
- Corrupted key files

**Solutions:**
```bash
# Re-provision from scratch
rm host_permanent_*.pem host_permanent_*.bin token_permanent_*.bin
python -m host.main /dev/ttyACM0 --provision
```

#### "Golden hash file not found"

**Cause:** Integrity verification requires golden hash

**Solution:**
```bash
# Provision includes golden hash setup
python -m host.main /dev/ttyACM0 --provision
```

---

## 📊 Message Types Reference

### System Control (0x00-0x0F)
- `0x00: T2H_ERROR` - Error from token
- `0x01: T2H_NACK` - Negative acknowledgment

### Phase 1: ECDH (0x20-0x2F)
- `0x20: H2T_ECDH_SHARE` - Host ephemeral pubkey + signature
- `0x21: T2H_ECDH_SHARE` - Token ephemeral pubkey + signature
- `0x22: T2H_CHANNEL_VERIFY_REQUEST` - Encrypted ping
- `0x23: H2T_CHANNEL_VERIFY_RESPONSE` - Encrypted pong

### Phase 2: Integrity (0x30-0x3F)
- `0x30: T2H_INTEGRITY_CHALLENGE` - Nonce challenge
- `0x31: H2T_INTEGRITY_RESPONSE` - Hash + signature
- `0x32: T2H_BOOT_OK` - Integrity check passed
- `0x33: T2H_INTEGRITY_FAIL_HALT` - Integrity check failed
- `0x34: H2T_BOOT_OK_ACK` - Host acknowledges BOOT_OK

### Phase 3: Runtime (0x40-0x4F)
- `0x40: H2T_HEARTBEAT` - Periodic heartbeat
- `0x41: T2H_HEARTBEAT_ACK` - Heartbeat acknowledgment

### Debug (0xF9-0xFE)
- `0xFE: DEBUG_MSG` - UTF-8 debug text
- `0xFD: H2T_TEST_RANDOM_REQUEST` - Request random number
- `0xFC: T2H_TEST_RANDOM_RESPONSE` - Random number (32 bytes)
- `0xFB: H2T_DEBUG_SET_HOST_PUBKEY` - Set host public key
- `0xFA: T2H_DEBUG_GET_TOKEN_PUBKEY` - Get token public key
- `0xF9: H2T_DEBUG_SET_GOLDEN_HASH` - Set golden hash

---

## 📚 Additional Resources

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Detailed architecture documentation
- **[Protocol Diagrams](../docs/)** - Visual protocol flow diagrams
- **[C Implementation](../src/)** - Token-side firmware
- **[Protocol Specification](../docs/INF2004_CS29_ProjectReport.md)** - Full protocol spec

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

**Code Style:**
- Follow PEP 8
- Use type hints
- Add docstrings
- Use Logger for output

---

## 📝 License

See [LICENSE.TXT](../LICENSE.TXT) in project root.

---

## 🎯 Next Steps

After successful setup, you can:

1. **Integrate into your application:**
   ```python
   from host.main import MASTRHost
   from host.crypto import NaiveCrypto
   
   host = MASTRHost(port="/dev/ttyACM0", crypto=NaiveCrypto())
   exit_code = host.run()
   ```

2. **Implement custom message handlers** for your use case

3. **Deploy to production** with TPM2 crypto backend (when available)

4. **Add application-specific phases** after Phase 2

---

**Questions?** Check [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical information.

**Last Updated:** 2024-10-26  
**Version:** 2.0 (Post Phase 1 Cleanup)
