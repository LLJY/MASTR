# Quick Start: Using MASTR with TPM2

## Prerequisites

1. **Your user is in the `tss` group** ✅ (Already done)
2. **TPM2 device is accessible** ✅ (Already verified)
3. **tpm2-pytss is installed** ✅ (Already installed)

## Running MASTR with TPM2

### Basic Usage

```bash
# Navigate to project directory
cd ~/Documents/embed\ project/MASTR

# Run with TPM2 crypto backend
python -m host.main --crypto tpm2 --port /dev/ttyACM0
```

### First Run (Key Provisioning)

On the first run, TPM2Crypto will:
1. Check if permanent keys exist in TPM
2. If not found, generate new ECC P-256 keypair in TPM
3. Store private key at persistent handle `0x81000080`
4. Exchange public keys with the token
5. Store token's public key in NVRAM at `0x01C00002`

You should see output like:
```
[INFO] TPM initialized successfully.
[INFO] Generating new permanent keypair in TPM...
[SUCCESS] Permanent keypair generated in TPM
[INFO] Exchanging public keys with token...
```

### Subsequent Runs

After initial provisioning, keys are loaded from TPM:
```bash
python -m host.main --crypto tpm2 --port /dev/ttyACM0
```

Output will show:
```
[INFO] TPM initialized successfully.
[SUCCESS] Permanent keys loaded from TPM
[INFO] Starting ECDH mutual authentication...
```

## Command Options

```bash
# Full syntax
python -m host.main \
    --crypto tpm2 \                    # Use TPM2 backend
    --port /dev/ttyACM0 \              # Serial port
    --baudrate 115200 \                # Baud rate (default: 115200)
    --verbose \                        # Enable verbose logging
    --provision                        # Force key regeneration
```

### Common Flags

- `--crypto tpm2` - Use TPM2 hardware crypto (required)
- `--port /dev/ttyACM0` - Serial port for token communication
- `--verbose` - Show detailed protocol messages
- `--provision` - Force regenerate keys (useful for testing)

## Testing TPM2 Standalone

Before running the full protocol, test TPM2 operations:

```bash
# Test TPM2 crypto implementation
python3 test_tpm2_updated.py
```

Expected output:
```
=== Testing TPM2 Basic Operations ===

1. Initializing TPM...
   ✓ TPM initialized successfully

2. Creating ECC primary key...
   ✓ ECC key created successfully
   ✓ Public key X: c89d3105d30bd6079...
   ✓ Public key Y: 69023b4ae67a214c5...

3. Testing ECDSA signing...
   ✓ Signature R: b14d61ada66fa642...
   ✓ Signature S: d58d2cc49e43b1c9...

4. Creating ECDH key...
   ✓ ECDH key created successfully
   ...

=== All Tests Passed! ===
```

## Comparing with File-Based Crypto

### Development Mode (File-Based)
```bash
# Uses files: host_permanent_privkey.pem, token_permanent_pubkey.bin
python -m host.main --crypto naive --port /dev/ttyACM0
```

### Production Mode (TPM2)
```bash
# Uses TPM2 hardware storage
python -m host.main --crypto tpm2 --port /dev/ttyACM0
```

**The protocol behavior is identical** - only key storage differs!

## Protocol Flow with TPM2

```
1. KEY PROVISIONING (Phase 0)
   ┌─────────────────────────────────────┐
   │ Load or generate keys in TPM        │
   │ Exchange public keys with token     │
   └─────────────────────────────────────┘

2. MUTUAL AUTHENTICATION (Phase 1)
   ┌─────────────────────────────────────┐
   │ Generate ephemeral keys in TPM      │
   │ Sign ephemeral keys with TPM        │
   │ Verify token's signature            │
   │ Compute ECDH secret in TPM          │
   │ Derive AES session key              │
   └─────────────────────────────────────┘

3. CHANNEL VERIFICATION (Phase 1.5)
   ┌─────────────────────────────────────┐
   │ Encrypted ping/pong challenge       │
   │ Confirms session key matches        │
   └─────────────────────────────────────┘

4. SECURE COMMUNICATION
   ┌─────────────────────────────────────┐
   │ All messages encrypted with         │
   │ AES-128-GCM using session key       │
   └─────────────────────────────────────┘
```

## Security Benefits

### With TPM2Crypto
- ✅ Private key **never leaves** TPM hardware
- ✅ Signing operations performed **inside TPM**
- ✅ ECDH computation performed **inside TPM**
- ✅ Keys persist across reboots
- ✅ Hardware-protected storage
- ✅ Resistant to software-based key extraction

### Without TPM2 (File-Based)
- ❌ Private key stored in PEM file on disk
- ❌ Vulnerable to file system access
- ❌ Key material in process memory
- ❌ Can be extracted by debugger

## Troubleshooting

### Error: "Failed to initialize TPM2 crypto"

Check device permissions:
```bash
ls -la /dev/tpm*
groups
```

### Error: "ModuleNotFoundError: No module named 'tpm2_pytss'"

Install the library:
```bash
sudo pacman -S python-tpm2-pytss
```

### TPM has old keys from previous test

Reset TPM storage:
```bash
# Clear persistent key
tpm2_evictcontrol -C o -c 0x81000080

# Clear NVRAM
tpm2_nvundefine 0x01C00002 -C o

# Or use --provision flag
python -m host.main --crypto tpm2 --provision
```

## What's Next?

1. **Connect your token** to `/dev/ttyACM0`
2. **Run with TPM2**: `python -m host.main --crypto tpm2 --port /dev/ttyACM0`
3. **Watch the protocol execute** with full TPM2 hardware security!

The entire ECDH key exchange, signing, and encryption now happens with **hardware-backed cryptography**!
