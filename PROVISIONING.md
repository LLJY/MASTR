# MASTR Provisioning Guide

## Overview

Provisioning is the one-time setup process to pair a host with a MASTR token. Both sides generate permanent keypairs and exchange public keys manually.

## Prerequisites

- TPM2 available on host system
- MASTR token powered and in provisioning mode (unprogrammed)
- Token WiFi AP accessible (SSID shown on token display)

## Provisioning Steps

### 1. Generate Host Keypair

```bash
python -m host.provision --regenerate
```

**Output:** Displays host public key (128 hex characters)
**Action:** Copy this hex string

### 2. Program Token

1. Connect to token WiFi AP
2. Open browser: http://192.168.4.1
3. Paste host public key into HTML UI
4. Click "Provision"
5. **Copy token public key** displayed on screen

### 3. Store Token Public Key on Host

```bash
python -m host.provision --set-token-pubkey <token-pubkey-hex>
```

### 4. Verify Provisioning

```bash
python -m host.provision --verify
```

**Expected output:**
```
✓ Host keypair exists (TPM2 0x81000080)
✓ Token pubkey stored (TPM2 NVRAM 0x01C00002)
Provisioning Complete!
```

## What Gets Stored

**Host (TPM2):**
- Host permanent private key → TPM2 handle 0x81000080
- Token permanent public key → TPM2 NVRAM 0x01C00002

**Token (ATECC608A):**
- Token permanent private key → Slot 0 (hardware-protected)
- Host permanent public key → Slot 8
- Golden hash → Slot 8 Block 2 (programmed separately via HTML UI)

## Golden Hash Setup

The golden hash is computed from `/boot/vmlinuz` (or configured file) at runtime. During provisioning, you must also:

1. Compute SHA256 of your integrity file: `sha256sum /boot/vmlinuz`
2. Paste the hash into token HTML UI
3. Token stores this as the reference for integrity verification

## After Provisioning

1. Copy `host/bootstrap.py` into initramfs
2. Configure initramfs to run bootstrap on boot
3. Reboot system
4. Token will verify host integrity before allowing boot

## Troubleshooting

**"Host keypair already exists"**
- Use `--regenerate` flag to force regeneration (this will unpair the token)

**"Token pubkey not found"**
- Ensure you ran `--set-token-pubkey` with correct hex string
- Verify hex string is exactly 128 characters (64 bytes)

**"TPM2 not available"**
- Check TPM2 is enabled in BIOS
- Verify `tpm2-tools` installed: `tpm2_getcap properties-fixed`

## View Current Status

```bash
python -m host.provision
```

Shows:
- Whether host keypair exists
- Whether token pubkey is stored
- TPM2 handles/indices used
