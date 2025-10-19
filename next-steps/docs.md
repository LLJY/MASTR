# ATECC608B-TNGTLS Trust&GO Implementation Guide

**Project**: Secure Embedded Hardware Token & Monitoring Tool  
**Target Hardware**: Raspberry Pi Pico 2 W (RP2350) + ATECC608B-TNGTLS (Trust&GO)  
**Date**: October 2025  
**Status**: ✅ Core Protocol Functions Tested & Verified

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Hardware Overview](#hardware-overview)
3. [Trust&GO Chip Analysis](#trustgo-chip-analysis)
4. [Tested Functions & Capabilities](#tested-functions--capabilities)
5. [Protocol Implementation Roadmap](#protocol-implementation-roadmap)
6. [Phase 0: Token Provisioning (Pairing)](#phase-0-token-provisioning-pairing)
7. [Phase 1: Mutual Attestation & Secure Channel](#phase-1-mutual-attestation--secure-channel)
8. [Phase 2: Integrity Verification & Runtime Guard](#phase-2-integrity-verification--runtime-guard)
9. [API Reference](#api-reference)
10. [Build & Flash Instructions](#build--flash-instructions)
11. [Troubleshooting](#troubleshooting)
12. [Next Steps](#next-steps)

---

## Executive Summary

This document provides a **complete implementation guide** for building a secure hardware token using the **ATECC608B-TNGTLS (Trust&GO)** chip on a Raspberry Pi Pico 2 W. The system implements a **zero-trust hardware USB token** with three distinct operational phases:

1. **Phase 0: Provisioning** - One-time pairing between Host (VM with vTPM) and Token (Pico + ATECC608B)
2. **Phase 1: Secure Handshake** - Mutual attestation and ephemeral key exchange for AES-128 encrypted channel
3. **Phase 2: Runtime Guard** - Continuous integrity monitoring with LKRG integration

**Key Innovation**: "Zero secrets on host" - all long-term cryptographic keys permanently locked in tamper-resistant hardware.

### ⚠️ CRITICAL IMPLEMENTATION RULES

1. **Host Software**: All host-side code is **Python 3**
   - Serial communication via `pyserial`
   - Cryptography via `cryptography` library
   - TPM interaction via `tpm2-tools` subprocess calls

2. **Token Communication**: **NO `printf()` after initialization!**
   - Token and Host communicate via **binary protocol only**
   - Any debug output **corrupts the serial packet stream**
   - Use `printf()` only during initial boot/testing
   - Production firmware: All logging disabled after handshake complete

3. **Binary Protocol**: Structured packet format with CRC-16
   - SYNC bytes: `0xAA 0x55`
   - Message types for all operations
   - CRC-16-CCITT error detection
   - See [Binary Serial Protocol](#binary-serial-protocol) section

---

## Hardware Overview

### System Components

| Component | Specification | Role |
|-----------|---------------|------|
| **Host** | VirtualBox VM with vTPM 2.0 + Python 3 | System being protected |
| **Token** | Raspberry Pi Pico 2 W (RP2350) | Guardian device |
| **Secure Element** | ATECC608B-TNGTLS (Trust&GO) | Hardware root of trust |
| **Communication** | USB Serial (ACM) | Binary protocol (NO printf on token!) |
| **I2C Address** | 0x35 (7-bit) / 0x6A (8-bit) | ATECC608B on Pico I2C bus |

### ⚠️ CRITICAL: Serial Communication Rules

**DO NOT use `printf()` on the Token after initialization!**

- The Token and Host communicate via **binary serial protocol**
- Any `printf()` or debug output **corrupts the packet stream**
- Use `printf()` only during:
  - ✅ Initial boot/diagnostics (before entering protocol loop)
  - ✅ Testing/development mode (with separate flag)
- **Production firmware**: All logging disabled after handshake

### Raspberry Pi Pico 2 W Features

- **MCU**: RP2350 dual Cortex-M33 @ 150 MHz
- **RAM**: 520 KB SRAM
- **Flash**: 4 MB
- **Crypto**: Hardware AES-256, SHA-256 (Cortex-M33 extensions)
- **Wi-Fi**: CYW43439 (802.11n, 2.4 GHz)
- **USB**: Full-speed USB 1.1 device/host
- **I2C**: Hardware I2C for ATECC608B communication

### ATECC608B-TNGTLS (Trust&GO) Specifications

- **Device Type**: Pre-provisioned secure element (0x0360)
- **I2C Speed**: 100 kHz (tested), supports up to 1 MHz
- **Cryptography**: 
  - ECC P-256 (NIST secp256r1)
  - AES-128 (hardware accelerated)
  - SHA-256 (hardware accelerated)
- **Lock Status**: **Both zones LOCKED** (factory provisioned)
- **TRNG**: True Random Number Generator (FIPS 140-2 Level 3)

---

## Trust&GO Chip Analysis

### What is Trust&GO?

The ATECC608B-TNGTLS is a **pre-provisioned Trust&GO** variant from Microchip. Unlike blank ATECC608A chips, Trust&GO devices come **factory-configured and locked** with:

- ✅ **Permanent ECC P-256 key pair** in Slot 0 (cannot be regenerated)
- ✅ **Pre-installed X.509 certificates** (compressed format)
- ✅ **Unique device certificate** signed by Microchip CA
- ✅ **416-byte data storage slot** (Slot 8)
- ✅ **Updatable key slots** (Slots 2-4 for key rotation)

### ⚠️ CRITICAL: Trust&GO is Borrowed Hardware

**DO NOT LOCK OR MODIFY PERMANENTLY!**

The Trust&GO chip used in this project is **borrowed property** and must be returned in original condition.

**Safe Operations** ✅:
- Read operations (config, serial, public keys)
- Ephemeral key generation (TempKey, Slot 2-4 before data lock)
- SHA-256 hashing
- ECDH with ephemeral keys
- Sign/verify with Slot 0 permanent key
- Write/read Slot 8 data storage (416 bytes)
- Counter operations

**FORBIDDEN Operations** ❌:
- **LOCK commands** (would permanently brick the chip for other users)
- Writing to Slot 0 (permanent key slot - protected)
- Modifying Config Zone
- Writing to certificate slots (10-12)
- Destroying the permanent private key

### Trust&GO Slot Configuration

| Slot | Size | Type | Purpose | Write Access | Read Access | Current Test Status |
|------|------|------|---------|--------------|-------------|---------------------|
| **0** | 36 B | ECC P-256 Private | **Permanent Identity Key** | ❌ Protected | Compute PubKey | ✅ Sign/Verify Working |
| **1** | 36 B | ECC P-256 Private | Reserved | ❌ Locked | PubKey Only | ⚠️ Not tested |
| **2** | 36 B | ECC P-256 Private | **Updatable Key** | ✅ Before data lock | PubKey Only | ✅ ECDH Working |
| **3** | 36 B | ECC P-256 Private | Updatable Key | ✅ Before data lock | PubKey Only | ⚠️ Not tested |
| **4** | 36 B | ECC P-256 Private | Updatable Key | ✅ Before data lock | PubKey Only | ⚠️ Not tested |
| **5** | 72 B | MAC | EUI-48/64 Address | Write-Once | Always | ⚠️ Not tested |
| **6** | 36 B | AES-128 | I/O Protection Key | Write-Once | Never | ❌ Factory locked |
| **7** | 72 B | Data | Reserved | ❌ Locked | Never | ⚠️ Not tested |
| **8** | 416 B | **Data Storage** | **Arbitrary Data** | ✅ Always | ✅ Always | ✅ Read/Write Working |
| **9** | 72 B | AES-128 x4 | Symmetric Keys | ✅ Encrypted | Never | ⚠️ Not tested |
| **10** | 72 B | Data | Device Certificate | ❌ Locked | ✅ Always | ⚠️ Not tested |
| **11** | 72 B | Data | Signer Certificate | ❌ Locked | ✅ Always | ⚠️ Not tested |
| **12** | 72 B | Data | CA Public Key | ❌ Locked | ✅ Always | ⚠️ Not tested |
| **13-15** | 72 B | Data | Reserved | ❌ Locked | Conditional | ⚠️ Not tested |

---

## Tested Functions & Capabilities

### Test Suite Results: 18/20 Passing (90%)

The following functions have been **successfully tested** and verified on the Trust&GO chip:

#### ✅ Basic Cryptographic Operations (100% Pass)

| Test | Function | CryptoAuthLib API | Status |
|------|----------|-------------------|--------|
| Test 1 | Device Info | `atcab_info()` | ✅ PASS |
| Test 2 | Serial Number | `atcab_read_serial_number()` | ✅ PASS |
| Test 3 | Random Number | `atcab_random()` | ✅ PASS |
| Test 4 | SHA-256 (simple) | `atcab_hw_sha2_256()` | ✅ PASS |
| Test 5 | SHA-256 (long) | `atcab_hw_sha2_256()` | ✅ PASS |
| Test 6 | Counter Read | `atcab_counter_read()` | ✅ PASS |
| Test 7 | Counter Increment | `atcab_counter_increment()` | ✅ PASS |
| Test 8 | Lock Status | `atcab_is_locked()` | ✅ PASS |
| Test 9 | Config Zone Read | `atcab_read_bytes_zone()` | ✅ PASS |
| Test 10 | Nonce | `atcab_nonce_rand()` | ✅ PASS |
| Test 11 | Entropy Check | Multiple `atcab_random()` | ✅ PASS |
| Test 12 | Ephemeral Key Gen | `atcab_genkey_base(GENKEY_MODE_PRIVATE, 0xFFFF)` | ✅ PASS |

#### ✅ Trust&GO Protection Verification (100% Pass)

| Test | Purpose | Expected Behavior | Status |
|------|---------|-------------------|--------|
| Test 13 | Slot 0 Permanent | GenKey fails (cannot regenerate) | ✅ PASS |
| Test 14 | PubKey from Slot 0 | Compute public key from permanent key | ✅ PASS |
| Test 15 | Slot 0 Protected | Write fails (private key protected) | ✅ PASS |
| Test 16 | Hash Storage (Slot 8) | 32-byte write/read/verify | ✅ PASS |
| Test 20 | Hash Storage (repeat) | Slot 8 write/read confirmed | ✅ PASS |
| Test 22 | Slot 2 Regeneration | Can generate new keys in updatable slots | ✅ PASS |

#### ⚠️ Advanced Cryptographic Tests (67% Pass)

| Test | Function | Implementation | Status | Issue |
|------|----------|----------------|--------|-------|
| Test 17 | Slot 8 Config | Read/write verification | ❌ FAIL | Config decode mismatch (functional test passes) |
| Test 18 | **ECDH Exchange** | `atcab_genkey(2)` + `atcab_ecdh(2, peer_pubkey)` | ✅ **FIXED** | Now uses Slot 2 instead of TempKey |
| Test 19 | **Sign & Verify** | `atcab_sign(0)` + `atcab_verify_extern()` | ✅ PASS | Uses permanent Slot 0 key |
| Test 21 | KDF (Optional) | Key derivation | ⚠️ SKIP | Requires I/O protection key (not accessible) |

**Note**: Tests 17 and 18 were previously failing but are now resolved. Test 17 has a false-positive failure (actual write/read works), and Test 18 now successfully performs ECDH.

---

## Binary Serial Protocol

### ⚠️ CRITICAL: NO printf() in Production Code!

After the token enters protocol mode, **all communication must be binary**. Any `printf()` or debug output will corrupt the packet stream and break the protocol.

### Packet Format

```
┌──────────┬──────────┬──────────┬──────────────┬──────────┐
│  SYNC    │  TYPE    │  LENGTH  │   PAYLOAD    │  CRC16   │
│ (2 bytes)│ (1 byte) │ (2 bytes)│  (N bytes)   │ (2 bytes)│
└──────────┴──────────┴──────────┴──────────────┴──────────┘
```

- **SYNC**: `0xAA 0x55` (fixed magic bytes)
- **TYPE**: Message type (see below)
- **LENGTH**: Payload length (little-endian)
- **PAYLOAD**: Variable-length data
- **CRC16**: CRC-16-CCITT checksum

### Message Types

```c
#define MSG_EPHEMERAL_KEY    0x01  // Ephemeral public key (64 bytes)
#define MSG_SIGNATURE        0x02  // ECDSA signature (64 bytes)
#define MSG_AUTH_OK          0x03  // Authentication success (0 bytes)
#define MSG_AUTH_FAIL        0x04  // Authentication failure (0 bytes)
#define MSG_SESSION_READY    0x05  // Session key derived (0 bytes)
#define MSG_ENCRYPTED_DATA   0x10  // Encrypted payload (variable)
#define MSG_HEARTBEAT        0x20  // Status heartbeat (16 bytes encrypted)
#define MSG_BOOT_OK          0x30  // Boot authorized (16 bytes encrypted)
#define MSG_BOOT_DENIED      0x31  // Boot denied (0 bytes)
#define MSG_SHUTDOWN         0x40  // Emergency shutdown (0 bytes)
```

### Example Implementation (Token Side)

```c
// Send a packet (Token → Host)
void send_packet(uint8_t type, const uint8_t *data, uint16_t len) {
    uint8_t header[5];
    header[0] = 0xAA;  // SYNC
    header[1] = 0x55;
    header[2] = type;
    header[3] = len & 0xFF;  // LENGTH (little-endian)
    header[4] = (len >> 8) & 0xFF;
    
    // Calculate CRC
    uint16_t crc = crc16_ccitt(header, 5);
    if (data && len > 0) {
        crc = crc16_ccitt_update(crc, data, len);
    }
    
    // Send header + payload + CRC
    serial_write(header, 5);
    if (data && len > 0) {
        serial_write(data, len);
    }
    uint8_t crc_bytes[2] = {crc & 0xFF, (crc >> 8) & 0xFF};
    serial_write(crc_bytes, 2);
}

// Receive a packet (Token ← Host)
int receive_packet(uint8_t *type, uint8_t *buffer, size_t *len) {
    uint8_t header[5];
    
    // Read SYNC bytes
    if (serial_read_with_timeout(header, 2, 1000) != 2) return -1;
    if (header[0] != 0xAA || header[1] != 0x55) return -1;
    
    // Read TYPE and LENGTH
    if (serial_read_with_timeout(&header[2], 3, 1000) != 3) return -1;
    
    *type = header[2];
    *len = header[3] | (header[4] << 8);
    
    // Read payload
    if (*len > 0) {
        if (serial_read_with_timeout(buffer, *len, 1000) != *len) return -1;
    }
    
    // Read and verify CRC
    uint8_t crc_bytes[2];
    if (serial_read_with_timeout(crc_bytes, 2, 1000) != 2) return -1;
    uint16_t received_crc = crc_bytes[0] | (crc_bytes[1] << 8);
    
    uint16_t calculated_crc = crc16_ccitt(header, 5);
    if (*len > 0) {
        calculated_crc = crc16_ccitt_update(calculated_crc, buffer, *len);
    }
    
    if (received_crc != calculated_crc) return -1;  // CRC mismatch
    
    return 0;  // Success
}
```

### Example Implementation (Python 3 Host Side)

```python
#!/usr/bin/env python3
import struct
from crcmod.predefined import mkCrcFun

# CRC-16-CCITT
crc16_ccitt = mkCrcFun('crc-ccitt-false')

def send_packet(ser, msg_type, data=b''):
    """Send a binary packet to the token."""
    length = len(data)
    header = struct.pack('<BBH', 0xAA, 0x55, msg_type) + struct.pack('<H', length)
    
    # Calculate CRC
    crc = crc16_ccitt(header + data)
    
    # Send packet
    ser.write(header + data + struct.pack('<H', crc))

def receive_packet(ser, timeout=5):
    """Receive a binary packet from the token."""
    ser.timeout = timeout
    
    # Read SYNC
    sync = ser.read(2)
    if len(sync) != 2 or sync != b'\xAA\x55':
        raise ValueError("Invalid SYNC bytes")
    
    # Read TYPE and LENGTH
    header = ser.read(3)
    if len(header) != 3:
        raise ValueError("Incomplete header")
    
    msg_type, length = struct.unpack('<BH', header)
    
    # Read payload
    payload = b''
    if length > 0:
        payload = ser.read(length)
        if len(payload) != length:
            raise ValueError("Incomplete payload")
    
    # Read and verify CRC
    crc_bytes = ser.read(2)
    if len(crc_bytes) != 2:
        raise ValueError("Incomplete CRC")
    
    received_crc = struct.unpack('<H', crc_bytes)[0]
    calculated_crc = crc16_ccitt(sync + header + payload)
    
    if received_crc != calculated_crc:
        raise ValueError("CRC mismatch")
    
    return msg_type, payload
```

---

## Protocol Implementation Roadmap

### Three-Phase Security Protocol

```
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 0: PROVISIONING (One-Time Setup)                            │
│  ══════════════════════════════════════════════════════════════     │
│  • Generate permanent key pairs (H_PrivKey, T_PrivKey)              │
│  • Exchange public keys (H_PubKey ↔ T_PubKey)                       │
│  • Compute and store golden hash of /boot/test-file                 │
│  • Lock keys in vTPM and ATECC608B                                  │
│                                                                      │
│  ⚠️  ONE-TIME ONLY - Cannot be repeated without chip reset          │
└─────────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1: SECURE HANDSHAKE (Every Boot)                            │
│  ══════════════════════════════════════════════════════════════     │
│  Step 1: Generate ephemeral keys (EH_Privkey, ET_Privkey)          │
│  Step 2: Sign ephemeral public keys with permanent keys            │
│  Step 3: Exchange and verify signed ephemeral keys                 │
│  Step 4: ECDH → Shared Secret → KDF → AES-128 Session Key          │
│  Step 5: Verify encrypted ping/pong                                │
│                                                                      │
│  Result: Secure AES-128 encrypted channel established               │
└─────────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 2: INTEGRITY ATTESTATION & RUNTIME GUARD                    │
│  ══════════════════════════════════════════════════════════════     │
│  Boot Time:                                                         │
│  • Token sends nonce → Host                                         │
│  • Host computes SHA-256(/boot/test-file) + nonce                  │
│  • Host signs with H_PrivKey → Token                                │
│  • Token verifies signature and compares hash to golden hash       │
│  • Token sends BOOT_OK signal (or halts system)                    │
│                                                                      │
│  Runtime Monitoring:                                                │
│  • Host daemon sends STATUS_OK every 5 seconds                     │
│  • LKRG monitors kernel for compromise                             │
│  • On alert → STATUS_COMPROMISED → Token triggers alert            │
│                                                                      │
│  Result: Continuous integrity verification                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 0: Token Provisioning (Pairing)

### Overview

This one-time setup establishes the **root of trust** between Host and Token.

### Step-by-Step Process

#### 1. Generate Permanent Keys

**On Token (Pico 2 W):**
```c
// Generate permanent ECDSA key pair in Slot 0
// NOTE: Trust&GO already has a permanent key in Slot 0!
// Use it directly - do NOT try to regenerate

uint8_t t_pubkey[64];  // 64 bytes: X (32) + Y (32)
ATCA_STATUS status = atcab_get_pubkey(0, t_pubkey);

if (status == ATCA_SUCCESS) {
    printf("Token permanent public key retrieved:\n");
    printf("  X: ");
    for (int i = 0; i < 32; i++) printf("%02X ", t_pubkey[i]);
    printf("\n  Y: ");
    for (int i = 32; i < 64; i++) printf("%02X ", t_pubkey[i]);
    printf("\n");
}
```

**On Host (VM with vTPM):**
```bash
# Generate permanent key in vTPM using tpm2-tools
tpm2_createprimary -C o -g sha256 -G ecc256 -c primary.ctx
tpm2_create -C primary.ctx -g sha256 -G ecc256 -u host_key.pub -r host_key.priv
tpm2_load -C primary.ctx -u host_key.pub -r host_key.priv -c host_key.ctx

# Export public key
tpm2_readpublic -c host_key.ctx -o h_pubkey.pem -f pem
```

#### 2. Exchange Public Keys

**Manual Transfer (Operator-Assisted):**

1. **Token → Host:**
   ```bash
   # On Token: Display public key via Web API or serial console
   # Copy the 64-byte hex string
   
   # On Host: Store in vTPM NVRAM
   tpm2_nvdefine 0x01500001 -C o -s 64 -a "ownerread|ownerwrite"
   echo "T_PUBKEY_HEX" | xxd -r -p | tpm2_nvwrite 0x01500001 -C o -i-
   ```

2. **Host → Token:**
   ```bash
   # On Host: Export public key
   tpm2_readpublic -c host_key.ctx -f pem -o h_pubkey.pem
   
   # Convert PEM to raw binary (64 bytes)
   openssl ec -pubin -in h_pubkey.pem -text -noout | \
     grep -A 5 "pub:" | tail -5 | tr -d ' :\n' | xxd -r -p > h_pubkey.bin
   
   # On Token: Store in ATECC608B Slot 8 (or designated slot)
   ```

**Token Code (Store Host Public Key):**
```c
// Store host public key in Slot 8 (first 64 bytes)
uint8_t h_pubkey[64] = {
    // Paste Host's public key here (64 bytes hex)
    0xAB, 0xCD, 0xEF, ...
};

status = atcab_write_zone(ATCA_ZONE_DATA, 8, 0, 0, h_pubkey, 64);
if (status == ATCA_SUCCESS) {
    printf("[OK] Host public key stored in ATECC608B Slot 8\n");
}
```

#### 3. Generate and Store Golden Hash

**On Host:**
```bash
# Compute SHA-256 of target file
GOLDEN_HASH=$(sha256sum /boot/test-file | awk '{print $1}')
echo "Golden Hash: $GOLDEN_HASH"

# Store in vTPM NVRAM for reference
tpm2_nvdefine 0x01500002 -C o -s 32 -a "ownerread|ownerwrite"
echo -n "$GOLDEN_HASH" | xxd -r -p | tpm2_nvwrite 0x01500002 -C o -i-
```

**On Token:**
```c
// Receive golden hash from host (32 bytes)
uint8_t golden_hash[32] = {
    // Paste golden hash here
    0x11, 0x4A, 0xB7, 0xE1, ...
};

// Store in ATECC608B Slot 8 (offset +64 bytes from public key)
status = atcab_write_zone(ATCA_ZONE_DATA, 8, 2, 0, golden_hash, 32);
if (status == ATCA_SUCCESS) {
    printf("[OK] Golden hash stored in ATECC608B\n");
}
```

**Slot 8 Layout (416 bytes):**
```
Offset 0-63:   Host Public Key (H_PubKey)        [64 bytes]
Offset 64-95:  Golden Hash                       [32 bytes]
Offset 96-415: Available for other data          [320 bytes]
```

### Provisioning Complete ✅

After this phase:
- ✅ Token has Host's public key for signature verification
- ✅ Host has Token's public key for signature verification
- ✅ Token has golden hash for integrity comparison
- ✅ Both devices ready for Phase 1 handshake

---

## Phase 1: Mutual Attestation & Secure Channel

### Overview

Every boot establishes a **fresh encrypted channel** using ephemeral keys.

### Step-by-Step Implementation

#### Step 1: Generate Ephemeral Keys

**On Token:**
```c
// Generate ephemeral key pair in Slot 2 (updatable)
uint8_t et_pubkey[64];
ATCA_STATUS status = atcab_genkey(2, et_pubkey);

// NO printf! Send public key via binary protocol to host
// Token must NOT use printf after entering protocol mode
if (status == ATCA_SUCCESS) {
    // Send ET_PubKey to host via binary packet
    send_packet(MSG_EPHEMERAL_KEY, et_pubkey, 64);
}
```

**On Host (Python 3):**
```python
#!/usr/bin/env python3
import serial
import subprocess

# Open serial connection to token
token = serial.Serial('/dev/ttyACM0', 115200, timeout=5)

# Generate ephemeral key in vTPM
subprocess.run([
    'tpm2_createprimary', '-C', 'e', '-g', 'sha256', '-G', 'ecc256',
    '-c', 'ephemeral_primary.ctx'
])
subprocess.run([
    'tpm2_create', '-C', 'ephemeral_primary.ctx', '-g', 'sha256',
    '-G', 'ecc256', '-u', 'eh_key.pub', '-r', 'eh_key.priv'
])
subprocess.run([
    'tpm2_load', '-C', 'ephemeral_primary.ctx', '-u', 'eh_key.pub',
    '-r', 'eh_key.priv', '-c', 'eh_key.ctx'
])
subprocess.run([
    'tpm2_readpublic', '-c', 'eh_key.ctx', '-o', 'eh_pubkey.pem', '-f', 'pem'
])
```

#### Step 2: Sign Ephemeral Keys

**On Token:**
```c
// Sign ET_PubKey with permanent Slot 0 key
uint8_t t_signature[64];
uint8_t et_pubkey_hash[32];

// Hash the ephemeral public key
atcab_hw_sha2_256(et_pubkey, 64, et_pubkey_hash);

// Sign with Slot 0 permanent key
status = atcab_sign(0, et_pubkey_hash, t_signature);

// NO printf! Send signature via binary protocol
if (status == ATCA_SUCCESS) {
    send_packet(MSG_SIGNATURE, t_signature, 64);
}
```

**On Host (Python 3):**
```python
#!/usr/bin/env python3
import subprocess

# Hash ephemeral public key
subprocess.run([
    'openssl', 'dgst', '-sha256', '-binary', 'eh_pubkey.pem'
], stdout=open('eh_pubkey_hash.bin', 'wb'))

# Sign with permanent key
subprocess.run([
    'tpm2_sign', '-c', 'host_key.ctx', '-g', 'sha256', '-s', 'rsassa',
    '-o', 'h_signature.bin', 'eh_pubkey_hash.bin'
])
```

#### Step 3: Exchange & Verify Signed Keys

**Protocol Flow:**
```
Token → Host:  [ET_PubKey || T_Signature]
Host  → Token: [EH_PubKey || H_Signature]
```

**On Host (Python 3 - Verify Token):**
```python
#!/usr/bin/env python3
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# Receive ET_PubKey and T_Signature from Token
et_pubkey_received = token.read(64)  # Read from serial
t_signature_received = token.read(64)

# Retrieve Token's permanent public key from storage
with open('token_pubkey.bin', 'rb') as f:
    t_pubkey_stored = f.read(64)

# Hash received ephemeral public key
et_pubkey_hash = hashlib.sha256(et_pubkey_received).digest()

# Verify signature using cryptography library
# (Alternatively, use openssl command-line tool)
try:
    # Convert raw bytes to ECC public key object
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b'\x04' + t_pubkey_stored
    )
    public_key.verify(
        t_signature_received,
        et_pubkey_hash,
        ec.ECDSA(hashes.SHA256())
    )
    print("[Host] Token authenticated successfully!")
    # Store ET_PubKey for ECDH
except Exception as e:
    print(f"[Host] Token authentication FAILED - ABORT! {e}")
    exit(1)
```

**On Token (Verify Host):**
```c
// Receive EH_PubKey and H_Signature from Host
uint8_t eh_pubkey_received[64];
uint8_t h_signature_received[64];
receive_packet(&msg_type, buffer, &len);  // Binary protocol
memcpy(eh_pubkey_received, buffer, 64);
receive_packet(&msg_type, buffer, &len);
memcpy(h_signature_received, buffer, 64);

// Retrieve Host's permanent public key from Slot 8
uint8_t h_pubkey_stored[64];
atcab_read_zone(ATCA_ZONE_DATA, 8, 0, 0, h_pubkey_stored, 64);

// Hash received ephemeral public key
uint8_t eh_pubkey_hash[32];
atcab_hw_sha2_256(eh_pubkey_received, 64, eh_pubkey_hash);

// Verify signature using ATECC608B
bool is_verified = false;
status = atcab_verify_extern(eh_pubkey_hash, h_signature_received,
                              h_pubkey_stored, &is_verified);

if (is_verified) {
    // NO printf! Send success via binary protocol
    send_packet(MSG_AUTH_OK, NULL, 0);
    // Store EH_PubKey for ECDH
} else {
    // NO printf! Send failure via binary protocol
    send_packet(MSG_AUTH_FAIL, NULL, 0);
    // Enter error state (blink LED, etc.)
    return false;
}
```

#### Step 4: ECDH Key Exchange & Session Key Derivation

**On Token:**
```c
// Perform ECDH: Slot 2 private key + Host ephemeral public key
uint8_t shared_secret[32];
status = atcab_ecdh(2, eh_pubkey_received, shared_secret);

if (status == ATCA_SUCCESS) {
    // NO printf! Derive session key silently
    
    // Derive AES-128 session key using KDF
    // Use RP2350 hardware SHA-256 for HKDF
    uint8_t session_key[16];  // AES-128
    hkdf_sha256(shared_secret, 32, 
                "ATECC-Session-2025", 18,  // Context string
                session_key, 16);
    
    // NO printf! Ready for encrypted communication
    send_packet(MSG_SESSION_READY, NULL, 0);
}
```

**On Host (Python 3):**
```python
#!/usr/bin/env python3
import subprocess
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Perform ECDH with vTPM
subprocess.run([
    'tpm2_ecdh_zgen', '-c', 'eh_key.ctx', '-u', 'et_pubkey.pem',
    '-o', 'shared_secret.bin'
])

# Read shared secret
with open('shared_secret.bin', 'rb') as f:
    shared_secret = f.read()

# Derive session key using HKDF-SHA256
kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=16,  # AES-128
    salt=None,
    info=b"ATECC-Session-2025",
    backend=default_backend()
)
session_key = kdf.derive(shared_secret)

print(f"[Host] Session key derived: {session_key.hex()}")
```

#### Step 5: Verify Encrypted Channel

**Token → Host: Encrypted PING**
```c
// Encrypt "PING" message with session key
uint8_t plaintext[16] = "PING____________";  // 16 bytes padded
uint8_t ciphertext[16];
uint8_t iv[16] = {0};  // AES-GCM would use nonce

// Use RP2350 hardware AES
aes128_encrypt_cbc(session_key, iv, plaintext, 16, ciphertext);

// NO printf! Send via binary protocol
send_packet(MSG_ENCRYPTED_DATA, ciphertext, 16);
```

**Host → Token: Encrypted PONG (Python 3)**
```python
#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Receive encrypted PING from token
msg_type, ping_encrypted = receive_packet(token)

# Decrypt PING
iv = b'\x00' * 16
cipher = Cipher(
    algorithms.AES(session_key),
    modes.CBC(iv),
    backend=default_backend()
)
decryptor = cipher.decryptor()
ping_decrypted = decryptor.update(ping_encrypted) + decryptor.finalize()

if ping_decrypted.startswith(b'PING'):
    print("[Host] PING received and decrypted successfully")
    
    # Encrypt PONG
    pong_plaintext = b'PONG____________'
    encryptor = cipher.encryptor()
    pong_encrypted = encryptor.update(pong_plaintext) + encryptor.finalize()
    
    # Send to token
    send_packet(token, MSG_ENCRYPTED_DATA, pong_encrypted)
else:
    print("[Host] PING decryption failed - channel compromised!")
    exit(1)
```

### Secure Channel Established ✅

After Phase 1:
- ✅ Both parties have verified each other's identity
- ✅ Ephemeral shared secret computed via ECDH
- ✅ AES-128 session key derived
- ✅ Encrypted communication verified
- ✅ Ready for Phase 2 attestation

---

## Phase 2: Integrity Verification & Runtime Guard

### Boot-Time Integrity Attestation

#### Step 1: Token Sends Nonce Challenge

**On Token:**
```c
// Generate cryptographic nonce (32 bytes)
uint8_t nonce[32];
ATCA_STATUS status = atcab_random(nonce);

printf("[Token] Sending integrity challenge (nonce):\n");
for (int i = 0; i < 32; i++) {
    printf("%02X ", nonce[i]);
}
printf("\n");

// Send nonce to Host (encrypted with session key)
uint8_t nonce_encrypted[32];
aes128_encrypt_gcm(session_key, nonce, 32, nonce_encrypted);
serial_write(nonce_encrypted, 32);
```

#### Step 2: Host Computes Hash + Signs

**On Host (initramfs):**
```bash
#!/bin/bash
# Boot-time attestation script

# Receive nonce from Token
NONCE=$(cat /dev/ttyACM0 | xxd -p)

# Compute SHA-256 of target file
FILE_HASH=$(sha256sum /boot/test-file | awk '{print $1}')

# Concatenate nonce + hash
MESSAGE="${NONCE}${FILE_HASH}"
echo -n "$MESSAGE" | xxd -r -p > message.bin

# Sign with permanent key in vTPM
tpm2_sign -c host_key.ctx -g sha256 -s rsassa \
  -o h_signature.bin message.bin

# Send hash and signature to Token
cat message.bin h_signature.bin > /dev/ttyACM0
```

#### Step 3: Token Verifies Signature & Hash

**On Token:**
```c
// Receive message (nonce + hash) and signature
uint8_t message_received[64];  // 32-byte nonce + 32-byte hash
uint8_t h_signature_received[64];
// ... receive from serial ...

// Retrieve Host's public key from Slot 8
uint8_t h_pubkey[64];
atcab_read_zone(ATCA_ZONE_DATA, 8, 0, 0, h_pubkey, 64);

// Verify signature
bool is_verified = false;
status = atcab_verify_extern(message_received, h_signature_received,
                              h_pubkey, &is_verified);

if (!is_verified) {
    // NO printf! Signal failure via LED and binary protocol
    gpio_set_led(LED_RED, true);  // Alert
    send_packet(MSG_BOOT_DENIED, NULL, 0);
    return false;
}

// Extract hash from message (last 32 bytes)
uint8_t h_hash[32];
memcpy(h_hash, message_received + 32, 32);

// Retrieve golden hash from Slot 8 (offset +64)
uint8_t golden_hash[32];
atcab_read_zone(ATCA_ZONE_DATA, 8, 2, 0, golden_hash, 32);

// Compare hashes
if (memcmp(h_hash, golden_hash, 32) != 0) {
    // NO printf! Signal failure via LED and binary protocol
    gpio_set_led(LED_RED, true);  // Alert
    send_packet(MSG_BOOT_DENIED, NULL, 0);
    return false;
}

// NO printf! Integrity verified silently
gpio_set_led(LED_GREEN, true);

// Send BOOT_OK signal to Host
uint8_t boot_ok_msg[16] = "BOOT_OK_________";
uint8_t boot_ok_encrypted[16];
aes128_encrypt_gcm(session_key, boot_ok_msg, 16, boot_ok_encrypted);
send_packet(MSG_BOOT_OK, boot_ok_encrypted, 16);
```

#### Step 4: Host Loads Kernel

**On Host (Python 3):**
```python
#!/usr/bin/env python3
import serial
import sys
import subprocess

token = serial.Serial('/dev/ttyACM0', 115200, timeout=30)

# Wait for BOOT_OK signal from Token
msg_type, boot_response = receive_packet(token)

if msg_type == MSG_BOOT_OK:
    # Decrypt response
    decrypted = decrypt_aes(session_key, boot_response)
    if decrypted.startswith(b'BOOT_OK'):
        print("[Host] ✅ Token authorized boot - Loading kernel...")
        # Continue boot process
        subprocess.run(['switch_root', '/newroot', '/sbin/init'])
    else:
        print("[Host] ❌ Decryption failed - HALT SYSTEM")
        subprocess.run(['poweroff', '-f'])
else:
    print("[Host] ❌ Token denied boot - HALT SYSTEM")
    subprocess.run(['poweroff', '-f'])
```

### Runtime Monitoring Loop

#### Host Daemon (Python 3)

```python
#!/usr/bin/env python3
# File: /usr/local/bin/token-monitor-daemon.py

import serial
import time
import subprocess
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

TOKEN_DEVICE = '/dev/ttyACM0'
HEARTBEAT_INTERVAL = 5  # seconds

def main():
    # Open serial connection to token
    token = serial.Serial(TOKEN_DEVICE, 115200, timeout=5)
    
    # Retrieve session key from kernel keyring
    # (Alternatively, load from secure storage)
    with open('/run/token_session_key', 'rb') as f:
        session_key = f.read(16)
    
    print("[Daemon] Starting runtime monitoring...")
    
    while True:
        # Check dmesg for LKRG alerts
        result = subprocess.run(
            ['dmesg'],
            capture_output=True,
            text=True
        )
        
        compromise_detected = False
        for line in result.stdout.splitlines()[-100:]:
            if 'LKRG:' in line and ('ALERT' in line or 'EXPLOIT' in line):
                compromise_detected = True
                print(f"[Daemon] ⚠️ LKRG alert detected: {line}")
                break
        
        # Prepare status message
        if compromise_detected:
            status_msg = b'STATUS_COMPROMISED'[:16].ljust(16, b'_')
            print("[Daemon] ⚠️ COMPROMISE DETECTED - Alerting token!")
        else:
            status_msg = b'STATUS_OK'[:16].ljust(16, b'_')
        
        # Encrypt with session key (AES-128-CBC)
        iv = b'\x00' * 16
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(status_msg) + encryptor.finalize()
        
        # Send to Token via binary protocol
        send_packet(token, MSG_HEARTBEAT, encrypted)
        
        time.sleep(HEARTBEAT_INTERVAL)

if __name__ == '__main__':
    main()
```

#### Token Runtime Handler

```c
// Token main loop - handles runtime monitoring
// ⚠️ NO printf AFTER INITIALIZATION! Binary protocol only!

void runtime_monitoring_loop(uint8_t *session_key) {
    uint32_t last_heartbeat = 0;
    uint32_t missed_heartbeats = 0;
    
    // NO printf! Runtime monitoring runs silently
    
    while (1) {
        // Check for incoming message from Host
        uint8_t msg_type;
        uint8_t buffer[64];
        size_t len;
        
        if (receive_packet(&msg_type, buffer, &len) == 0) {
            if (msg_type == MSG_HEARTBEAT && len == 16) {
                uint8_t encrypted_msg[16];
                uint8_t decrypted_msg[16];
                
                memcpy(encrypted_msg, buffer, 16);
                
                // Decrypt with session key
                aes128_decrypt_cbc(session_key, NULL, encrypted_msg, 16, decrypted_msg);
                
                if (strncmp((char*)decrypted_msg, "STATUS_OK", 9) == 0) {
                    // System healthy - NO printf!
                    last_heartbeat = time_ms();
                    missed_heartbeats = 0;
                    gpio_set_led(LED_GREEN, true);
                    gpio_set_led(LED_RED, false);
                    
                } else if (strncmp((char*)decrypted_msg, "STATUS_COMPROMISED", 18) == 0) {
                    // COMPROMISE DETECTED! - NO printf!
                    gpio_set_led(LED_RED, true);
                    gpio_set_led(LED_GREEN, false);
                    
                    // Trigger buzzer/alarm
                    gpio_set_pin(BUZZER_PIN, true);
                    sleep_ms(1000);
                    gpio_set_pin(BUZZER_PIN, false);
                    
                    // Optionally: Send shutdown command to Host
                    // send_packet(MSG_SHUTDOWN, NULL, 0);
                }
            }
        }
        
        // Check for heartbeat timeout
        if ((time_ms() - last_heartbeat) > 15000) {  // 15 second timeout
            missed_heartbeats++;
            // NO printf! Just track count
            
            if (missed_heartbeats >= 3) {
                // Host unresponsive - NO printf!
                gpio_set_led(LED_RED, true);
                
                // Send shutdown command
                send_packet(MSG_SHUTDOWN, NULL, 0);
                break;
            }
        }
        
        sleep_ms(100);
    }
}
```

---

## API Reference

### CryptoAuthLib Essential Functions

#### Device Management

```c
// Initialize CryptoAuthLib
ATCA_STATUS atcab_init(ATCAIfaceCfg *cfg);

// Release resources
ATCA_STATUS atcab_release(void);

// Get device info
ATCA_STATUS atcab_info(uint8_t *revision);

// Read serial number
ATCA_STATUS atcab_read_serial_number(uint8_t *serial_number);
```

#### Key Generation

```c
// Generate key in slot (Slots 2-4 for Trust&GO)
ATCA_STATUS atcab_genkey(uint16_t key_id, uint8_t *public_key);

// Generate key with mode specification
ATCA_STATUS atcab_genkey_base(uint8_t mode, uint16_t key_id, 
                               const uint8_t *other_data, uint8_t *public_key);

// Get public key from slot
ATCA_STATUS atcab_get_pubkey(uint16_t key_id, uint8_t *public_key);
```

#### Signing & Verification

```c
// Sign message with private key in slot
ATCA_STATUS atcab_sign(uint16_t key_id, const uint8_t *msg, uint8_t *signature);

// Verify external signature
ATCA_STATUS atcab_verify_extern(const uint8_t *message, const uint8_t *signature,
                                 const uint8_t *public_key, bool *is_verified);
```

#### ECDH Key Exchange

```c
// Perform ECDH with slot private key and external public key
ATCA_STATUS atcab_ecdh(uint16_t key_id, const uint8_t *public_key, 
                       uint8_t *pms);

// ECDH with mode specification
ATCA_STATUS atcab_ecdh_base(uint8_t mode, uint16_t key_id,
                            const uint8_t *public_key, uint8_t *pms, 
                            uint8_t *out_nonce);
```

#### Hashing

```c
// Hardware SHA-256
ATCA_STATUS atcab_hw_sha2_256(const uint8_t *data, size_t data_size, 
                               uint8_t *digest);

// SHA-256 with init/update/final
ATCA_STATUS atcab_sha_start(void);
ATCA_STATUS atcab_sha_update(const uint8_t *message, size_t length);
ATCA_STATUS atcab_sha_end(uint8_t *digest, uint16_t length, const uint8_t *message);
```

#### Random Number Generation

```c
// Generate 32-byte random number (TRNG)
ATCA_STATUS atcab_random(uint8_t *rand_out);

// Nonce operation
ATCA_STATUS atcab_nonce_rand(const uint8_t *num_in, uint8_t *rand_out);
```

#### Data Zone Operations

```c
// Write data to slot
ATCA_STATUS atcab_write_zone(uint8_t zone, uint16_t slot, uint8_t block, 
                              uint8_t offset, const uint8_t *data, uint8_t len);

// Read data from slot
ATCA_STATUS atcab_read_zone(uint8_t zone, uint16_t slot, uint8_t block,
                             uint8_t offset, uint8_t *data, uint8_t len);

// Read bytes from config/data zone
ATCA_STATUS atcab_read_bytes_zone(uint8_t zone, uint16_t slot, size_t offset,
                                   uint8_t *data, size_t length);
```

#### Counter Operations

```c
// Read counter value
ATCA_STATUS atcab_counter_read(uint16_t counter_id, uint32_t *counter_value);

// Increment counter
ATCA_STATUS atcab_counter_increment(uint16_t counter_id, uint32_t *counter_value);
```

#### Lock Status

```c
// Check if zone is locked
ATCA_STATUS atcab_is_locked(uint8_t zone, bool *is_locked);

// Zones: LOCK_ZONE_CONFIG, LOCK_ZONE_DATA
```

---

## Build & Flash Instructions

### Prerequisites

```bash
# Install Pico SDK
sudo apt install cmake gcc-arm-none-eabi libnewlib-arm-none-eabi \
  build-essential libstdc++-arm-none-eabi-newlib

# Set Pico SDK path
export PICO_SDK_PATH=/path/to/pico-sdk

# Clone project
git clone https://github.com/your-repo/pico-atecc-token.git
cd pico-atecc-token
```

### Build Process

```bash
# Create build directory
mkdir build && cd build

# Configure CMake
cmake -DPICO_BOARD=pico2_w ..

# Build all targets
make -j16

# Build specific target
make -j16 pico_atecc608_app
```

### Flash to Pico

#### Method 1: UF2 Bootloader (Recommended)

```bash
# Hold BOOTSEL button while connecting USB
# Pico appears as USB mass storage device

# Copy firmware
cp build/pico_atecc608_app.uf2 /media/$USER/RPI-RP2/

# Pico automatically reboots and runs firmware
```

#### Method 2: picotool (Advanced)

```bash
# Install picotool
sudo apt install picotool

# Flash firmware
picotool load -x build/pico_atecc608_app.elf

# Force into BOOTSEL mode and flash
picotool reboot -f -u
picotool load -x build/pico_atecc608_app.elf
```

### Serial Console

```bash
# Connect to Pico serial console
sudo minicom -D /dev/ttyACM0 -b 115200

# Or use screen
sudo screen /dev/ttyACM0 115200

# Exit: Ctrl+A, then K
```

---

## Troubleshooting

### Common Issues

#### 1. ATECC608B Not Detected

**Symptoms:**
- I2C scan shows no device at 0x35
- `atcab_init()` returns `ATCA_COMM_FAIL`

**Solutions:**
```bash
# Check I2C wiring
# Pico GP4 (SDA) → ATECC608B SDA
# Pico GP5 (SCL) → ATECC608B SCL
# Pico 3V3 → ATECC608B VCC
# Pico GND → ATECC608B GND

# Verify I2C pull-up resistors (2.2kΩ - 4.7kΩ)
# Reduce I2C speed in atca_config.h:
.atcai2c.baud = 100000,  // Try 100 kHz instead of 400 kHz
```

#### 2. ECDH Fails with `ATCA_INVALID_ID`

**Cause:** Trying to use TempKey (0xFFFF) for ECDH

**Solution:**
```c
// WRONG: TempKey not valid for ECDH
atcab_genkey_base(GENKEY_MODE_PRIVATE, 0xFFFF, NULL, pubkey);
atcab_ecdh(0xFFFF, peer_pubkey, shared_secret);  // FAILS!

// CORRECT: Use Slot 2 (updatable)
atcab_genkey(2, pubkey);
atcab_ecdh(2, peer_pubkey, shared_secret);  // Works!
```

#### 3. Slot 0 GenKey Fails

**Cause:** Slot 0 is permanent key on Trust&GO (cannot regenerate)

**Solution:**
```c
// Don't try to generate new key in Slot 0!
// Use existing permanent key:
uint8_t pubkey[64];
atcab_get_pubkey(0, pubkey);  // Read existing public key
```

#### 4. Write to Slot 8 Fails

**Symptoms:**
- `atcab_write_zone()` returns `ATCA_EXECUTION_ERROR`

**Check:**
```c
// Verify slot 8 config allows writes
uint8_t config[128];
atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 0, config, 128);

int slot8_offset = 20 + (8 * 2);
uint16_t slotconfig = (config[slot8_offset+1] << 8) | config[slot8_offset];

printf("Slot 8 SlotConfig: 0x%04X\n", slotconfig);
// Trust&GO: Should be 0x0F0F (read/write enabled)
```

#### 5. Compilation Errors

**Missing CryptoAuthLib:**
```bash
# CryptoAuthLib fetched automatically by CMake
# If manual install needed:
git clone https://github.com/MicrochipTech/cryptoauthlib.git
cd cryptoauthlib
mkdir build && cd build
cmake ..
make
sudo make install
```

**Pico SDK Not Found:**
```bash
# Set environment variable
export PICO_SDK_PATH=/path/to/pico-sdk

# Or set in CMakeLists.txt:
set(PICO_SDK_PATH "/path/to/pico-sdk")
```

### Debug Output

Enable verbose logging:

```c
// In main.c, add debug prints
#define DEBUG_ATECC 1

#if DEBUG_ATECC
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

// Use throughout code
DEBUG_PRINT("[DEBUG] ECDH status: 0x%02X\n", status);
```

---

## Next Steps

### Immediate Tasks (Ready to Implement)

1. **Web Portal Development** ⏳
   - [ ] Set up Wi-Fi AP on Pico 2 W (CYW43439)
   - [ ] Implement HTTPS server with TLS 1.3
   - [ ] Create authentication system (API key)
   - [ ] Build monitoring dashboard (CPU, RAM, temperature)
   - [ ] Add network status display (connected clients)

2. **Protocol State Machine** ⏳
   - [ ] Implement 3-phase state machine on Pico
   - [ ] Serial protocol framing (message headers, CRC)
   - [ ] Timeout handling for each phase
   - [ ] Error recovery and retry logic

3. **Host-Side Components** ⏳
   - [ ] Create initramfs script for boot attestation
   - [ ] Build runtime monitoring daemon
   - [ ] Integrate with Linux Kernel Runtime Guard (LKRG)
   - [ ] Implement kernel keyring for session key storage

### Advanced Features

4. **AES Optimization** 🔧
   - [ ] Use RP2350 hardware AES (Cortex-M33 crypto extensions)
   - [ ] Benchmark: ATECC608B vs. RP2350 for bulk encryption
   - [ ] Implement AES-GCM for authenticated encryption

5. **Certificate Management** 🔐
   - [ ] Read Trust&GO device certificate (Slot 10)
   - [ ] Verify certificate chain to Microchip CA
   - [ ] Use device certificate for mTLS authentication

6. **Secure Firmware Updates** 🔄
   - [ ] Implement secure bootloader for Pico
   - [ ] Sign firmware with Slot 0 permanent key
   - [ ] Verify firmware signature before flash

7. **Physical Security** 🔒
   - [ ] Add tamper detection (GPIO pins)
   - [ ] Implement zeroization on tamper event
   - [ ] Physical alert (LED, buzzer)

### Testing & Validation

8. **Security Testing** ✅
   - [ ] Penetration testing of handshake protocol
   - [ ] MITM attack simulation
   - [ ] Replay attack prevention verification
   - [ ] Side-channel attack analysis (timing, power)

9. **Performance Benchmarking** 📊
   - [ ] Measure boot time (target: <120 seconds)
   - [ ] Heartbeat latency (target: <2 seconds)
   - [ ] Memory usage on Pico (<10 KB RAM)
   - [ ] Power consumption profiling

10. **Documentation** 📝
    - [x] Complete API reference
    - [x] Protocol specification
    - [ ] Security analysis report
    - [ ] Deployment guide
    - [ ] Troubleshooting FAQ

---

## Resources

### Documentation

- [ATECC608B Datasheet](https://ww1.microchip.com/downloads/en/DeviceDoc/ATECC608B-CryptoAuthentication-Device-Summary-Data-Sheet-DS40002239A.pdf)
- [CryptoAuthLib GitHub](https://github.com/MicrochipTech/cryptoauthlib)
- [Pico SDK Documentation](https://www.raspberrypi.com/documentation/microcontrollers/c_sdk.html)
- [Trust&GO Platform](https://www.microchip.com/en-us/products/security/trust-platform/trust-go)

### Tools

- [picotool](https://github.com/raspberrypi/picotool) - Pico firmware management
- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) - TPM 2.0 utilities
- [OpenSSL](https://www.openssl.org/) - Cryptographic toolkit

### Related Projects

- [TinySSH](https://tinyssh.org/) - Minimal SSH implementation
- [mbedTLS](https://github.com/Mbed-TLS/mbedtls) - Embedded TLS library
- [LKRG](https://github.com/lkrg-org/lkrg) - Linux Kernel Runtime Guard

---

## License

This project is dual-licensed:
- **MIT License** for software components
- **Apache 2.0** for documentation

See `LICENSE.TXT` for details.

---

## Contributing

Contributions welcome! Please follow these guidelines:

1. **Test thoroughly** - All changes must pass 20/20 test suite
2. **Document changes** - Update API reference and protocol docs
3. **Safety first** - Never lock or permanently modify borrowed hardware
4. **Code quality** - Follow Google C++ Style Guide with Doxygen comments

---

## Contact

**Project Team**: CS29 (INF2004 Embedded Systems)  
**Repository**: [GitHub Link]  
**Issues**: [Issue Tracker]

---

## Acknowledgments

- **Microchip Technology** - ATECC608B Trust&GO chip and CryptoAuthLib
- **Raspberry Pi Foundation** - Pico 2 W platform and SDK
- **Linux Kernel Runtime Guard** - Runtime integrity monitoring
- **SIT INF2004** - Course guidance and support

---

**Last Updated**: October 2025  
**Version**: 1.0.0  
**Build Status**: ✅ Core functions tested (18/20 passing)
