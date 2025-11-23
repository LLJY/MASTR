# MASTR: Mutual Attested Secure Token for Robotics

MASTR is a security-focused embedded system that establishes a secure communication channel between a host system and a hardware token (Raspberry Pi Pico W/Pico 2 W + ATECC608A). It utilizes a three-phase protocol to ensure mutual attestation, secure channel establishment, and runtime integrity verification.

Navigate to [Quick Start Guide](#quick-start-guide) to get started.

[![Protocol](https://img.shields.io/badge/Protocol-MASTR-blue)](docs/)
[![Firmware](https://img.shields.io/badge/Firmware-RP2040%2FRP2350-green)](src/)
[![Host](https://img.shields.io/badge/Host-Python%203.13+-brightgreen)](host/)
[![Status](https://img.shields.io/badge/Status-Active-success)]()

---

## Table of Contents

- [Protocol Overview](#protocol-overview)
  - [Phase 1: Host-Token Pairing Process](#phase-1-host-token-pairing-process)
  - [Phase 2: Mutual Attestation & Secure Channel Establishment](#phase-2-mutual-attestation--secure-channel-establishment)
  - [Phase 3: Integrity Verification & Runtime Guard](#phase-3-integrity-verification--runtime-guard)
  - [Runtime Heartbeat](#runtime-heartbeat)
  - [Shutdown Policy](#shutdown-policy)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Hardware Requirements](#hardware-requirements)
  - [Software Requirements](#software-requirements)
- [Quick Start Guide](#quick-start-guide)
- [Building the Firmware](#building-the-firmware)
  - [Build for Raspberry Pi Pico 2 W (RP2350)](#build-for-raspberry-pi-pico-2-w-rp2350)
  - [Flashing the Firmware](#flashing-the-firmware)
  - [Build Options](#build-options)
- [Running the Host Application](#running-the-host-application)
  - [Installation](#installation)
  - [Basic Usage](#basic-usage)
  - [Command-Line Options](#command-line-options)
  - [Expected Output](#expected-output)
- [Provisioning Instructions](#provisioning-instructions)
  - [Method 1: HTML UI (Production - Recommended)](#method-1-html-ui-production---recommended)
  - [Method 2: Python CLI Provisioning Tool (Standalone)](#method-2-python-cli-provisioning-tool-standalone)
  - [Method 3: Python API Client (Debug/Testing)](#method-3-python-api-client-debugtesting)
  - [Method 4: Serial Protocol (Legacy/Debug)](#method-4-serial-protocol-legacydebug)
- [Testing](#testing)
  - [Running Unit Tests](#running-unit-tests)
  - [Generating Coverage Reports](#generating-coverage-reports)
  - [Interpreting Test Results](#interpreting-test-results)
- [Troubleshooting](#troubleshooting)
  - [Serial Port Issues](#serial-port-issues)
  - [Provisioning Failures](#provisioning-failures)
  - [Protocol Errors](#protocol-errors)
  - [TPM2 Issues](#tpm2-issues)
- [Project Structure](#project-structure)
- [License](#license)

---

## Protocol Overview

The MASTR protocol is divided into three distinct phases:

### Phase 1: Host-Token Pairing Process

This initial, one-time pairing process establishes a trusted relationship between the host and the token.

<img src="docs/Embedded-pairing-process.drawio (1).png" alt="Host-Token Pairing Process" width="500"/>

1.  **Key Generation:** Both the host and the token generate a new, persistent ECDSA keypair.
2.  **Public Key Exchange:** The host and token exchange their public keys.
3.  **Golden Hash:** The host generates a "golden hash" of its boot file and shares it with the token. This hash represents the known-good state of the host's software.

### Phase 2: Mutual Attestation & Secure Channel Establishment

This phase is performed on every boot to establish a secure session.

<img src="docs/Secure Channel Phase 2 embed.drawio.png" alt="Secure Channel Establishment" width="500"/>

1.  **Ephemeral Key Generation:** The host and token each generate an ephemeral ECDH keypair.
2.  **Signed Key Exchange:** They exchange their ephemeral public keys, signing them with their persistent private keys from the pairing phase.
3.  **Signature Verification:** Each party verifies the signature on the received ephemeral public key using the other's stored persistent public key.
4.  **Secure Secret Derivation:** A shared secret is derived using the ECDH algorithm.
5.  **Session Key Generation:** A KDF (Key Derivation Function) is used to generate an AES-128 session key from the shared secret.
6.  **Channel Verification:** The channel is verified with an encrypted ping-pong exchange.

### Phase 3: Integrity Verification & Runtime Guard

This phase ensures the host is running the correct software before allowing it to boot.

<img src="docs/Integrity Attest Phase 3 embed.drawio.png" alt="Integrity Attestation" width="500"/>

1.  **Integrity Challenge:** The token sends a random nonce to the host.
2.  **Hash Calculation:** The host calculates a hash of its current boot file.
3.  **Signed Response:** The host signs the hash and the nonce with its persistent private key and sends the signature and hash to the token.
4.  **Verification:** The token verifies the signature and compares the received hash with the stored "golden hash".
5.  **Boot Signal:** If the verification is successful, the token sends a `T2H_BOOT_OK` signal to the host; otherwise, it sends `T2H_INTEGRITY_FAIL_HALT`.

### Runtime Heartbeat

After a successful boot, the host sends periodic heartbeat messages to the token to maintain the session.

### Shutdown Policy

The system will shut down under the following conditions:

*   A protocol phase is not completed within 30 seconds.
*   Either the host or token sends a "no-go" signal.
*   The `T2H_BOOT_OK` signal is not received within 2 minutes of starting the attestation process.
*   The heartbeat timeout occurs more than 3 times.

---

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed and configured:

#### Hardware Requirements

- **Raspberry Pi Pico 2 W** (with WiFi)
- **ATECC608A/B/C** secure element (connected via I2C at address 0x35) i2c address is configurable
- **USB cable** for programming and serial communication
- **Host computer** (Linux, macOS, or POSIX Compliant OS ONLY)

#### Software Requirements

**For Firmware Development:**
- [Raspberry Pi Pico SDK](https://github.com/raspberrypi/pico-sdk) (v1.5.0 or later)
- **CMake** (version 3.13 or later)
- **ARM GCC Compiler** (arm-none-eabi-gcc)
- **Python 3.8+** (for build scripts)

**For Host Application:**
- **Python 3.8+**
- **pip** (Python package manager)
- **pySerial** library
- **cryptography** library
- **(Optional) TPM2** hardware and **tpm2-pytss** library for production deployment

**Platform-Specific Setup:**

**Linux:**
```bash
# Install ARM GCC toolchain
sudo apt-get update
sudo apt-get install gcc-arm-none-eabi libnewlib-arm-none-eabi build-essential

# Install CMake (if not already installed)
sudo apt-get install cmake

# Install Pico SDK
git clone https://github.com/raspberrypi/pico-sdk.git
cd pico-sdk
git submodule update --init
export PICO_SDK_PATH=$(pwd)

# Add user to dialout group for serial access
sudo usermod -a -G dialout $USER
# Log out and back in for changes to take effect
```

**macOS:**
```bash
# Install ARM GCC toolchain
brew tap ArmMbed/homebrew-formulae
brew install arm-none-eabi-gcc

# Install CMake
brew install cmake

# Install Pico SDK
git clone https://github.com/raspberrypi/pico-sdk.git
cd pico-sdk
git submodule update --init
export PICO_SDK_PATH=$(pwd)
```

---

## Quick Start Guide

Follow these steps to get MASTR up and running from zero to a fully provisioned, running system:

### Step 1: Clone the Repository

```bash
git clone https://github.com/LLJY/MASTR
cd MASTR-NEW
```

### Step 2: Build the Firmware

```bash
# For Raspberry Pi Pico 2W
mkdir build
cd build
# compiling in debug mode recommended for testing
cmake .. -DPICO_BOARD=pico2_w -DENABLE_DEBUG=ON
make -j$(nproc)
```

### Step 3: Flash the Firmware (Picotool recommended)

Run the following command in the `build` folder:
   ```bash
   picotool load -f pico_project_template.uf2
   ```

The Pico W will automatically reboot and start running MASTR

### Step 4: Install Host Dependencies

```bash
cd host/
pip install -r requirements.txt

# pytss may fail to install.
```

### Step 5: Provision the System

Connect to the token's WiFi AP and use the HTML provisioning interface (see [Method 1: HTML UI](#method-1-html-ui-production---recommended) for detailed instructions).

### Step 6: Run the Host Application

```bash
# After provisioning via HTML UI
python -m host.main /dev/ttyACM0
```

You should see successful authentication and a secure channel established!

---

## Building the Firmware

The firmware currently only runs on the Pico 2W, the standard Pico W is supported, but not tested.

### Build for Raspberry Pi Pico 2W

```bash
# From project root
mkdir build
cd build

# Configure for Pico 2W (RP2350 with WiFi)
cmake .. -DPICO_BOARD=pico2_w  -DENABLE_DEBUG=ON

# Build
make -j$(nproc)

# The output file will be: build/pico_project_template.uf2
```

### Flashing the Firmware

**Using Picotool Method (Recommended):**
1. After compilation, run the following command:
   ```bash
   # Linux/macOS
   picotool load -f pico_project_template.uf2
   ```
4. Device will **automatically reboot** and run the firmware

**Verify Firmware is Running:**
- The token's WiFi AP should appear as `MASTR-TOKEN` (check for SSID in your WiFi list)
- Serial output should be visible on `/dev/ttyACM0` at 115200 baud

### Build Options

**Debug Build:**
```bash
cmake .. -DPICO_BOARD=pico2_w -DCMAKE_BUILD_TYPE=Debug
make
```

**Release Build (Optimized):**
```bash
cmake .. -DPICO_BOARD=pico2_w -DCMAKE_BUILD_TYPE=Release
make
```

**Clean Build:**
```bash
# Remove build directory and start fresh
cd ..
rm -rf build
mkdir build
cd build
cmake .. -DPICO_BOARD=pico2_w
make
```

**Build Specific Targets:**
```bash
make mastr          # Build main firmware
make test_runner    # Build unit tests
```

---

## Running the Host Application

The host application is a Python-based implementation that communicates with the MASTR token over serial.

### Installation

```bash
# Navigate to host directory
cd host/

# Install dependencies
pip install -r requirements.txt
```

**Manual Installation:**
```bash
pip install pyserial cryptography

# For TPM2 support (production)
# Arch Linux
sudo pacman -S python-tpm2-pytss

# Ubuntu/Debian
sudo apt-get install python3-tpm2-pytss
```

### Basic Usage

```bash
# Run with existing keys (after provisioning)
python -m host.main /dev/ttyACM0

# Run with verbose output
python -m host.main /dev/ttyACM0 -v

# Use different serial port
python -m host.main /dev/ttyUSB0

# Windows
python -m host.main COM3

# macOS
python -m host.main /dev/tty.usbmodem14101
```

### Command-Line Options

```bash
python -m host.main <port> [options]
```

| Option | Description | Default | Notes |
|--------|-------------|---------|-------|
| `port` | Serial port device | *Required* | e.g., /dev/ttyACM0, COM3 |
| `-b, --baudrate` | Baud rate | 115200 | Match firmware setting |
| `-v, --verbose` | Enable verbose logging | False | Shows detailed protocol steps |
| `--crypto` | Crypto backend | `naive` | Options: `naive`, `tpm2` |
| `--provision` | [DEBUG] Provision via HTTP API | False | Use HTML UI instead |
| `--debug-override-provision` | [DEBUG] Use serial protocol | False | Legacy method |
| `--golden-hash-file` | File to hash for integrity | `b"h\0"` | Path to file for golden hash |

**Examples:**

```bash
# Standard usage (after HTML provisioning)
python -m host.main /dev/ttyACM0

# With TPM2 crypto backend (production)
python -m host.main /dev/ttyACM0 --crypto tpm2

# Verbose mode for debugging
python -m host.main /dev/ttyACM0 -v

# Custom baud rate
python -m host.main /dev/ttyACM0 -b 9600

# Specify golden hash file
python -m host.main /dev/ttyACM0 --golden-hash-file /boot/vmlinuz
```

### Expected Output

When running successfully, you should see:

```
============================================================
MASTR Host - Production Protocol Implementation
============================================================
Port: /dev/ttyACM0
Crypto: NaiveCrypto (or TPM2Crypto)

=== Connecting to Token ===
✓ Connected to /dev/ttyACM0

=== Phase 0: Key Loading ===
✓ Permanent keys loaded from storage

=== Phase 1: Mutual Authentication (ECDH) ===
[STEP 1] Generating ephemeral ECDH keypair...
  ✓ Ephemeral keypair generated
[STEP 2] Signing ephemeral pubkey with permanent key...
  ✓ Signed ephemeral pubkey
[STEP 3] Sending H2T_ECDH_SHARE...
  ✓ Sent
[STEP 4] Waiting for T2H_ECDH_SHARE...
  ✓ Received token's ephemeral pubkey + signature
[STEP 5] Verifying token's signature...
  ✓ Signature valid
[STEP 6] Computing ECDH shared secret...
  ✓ Shared secret: 32 bytes
[STEP 7] Deriving session key (HKDF-SHA256)...
  ✓ Session key: a1b2c3d4e5f67890...

=== Phase 1.5: Channel Verification ===
[STEP 1] Waiting for encrypted ping...
  ✓ Ping received
[STEP 2] Sending encrypted pong...
  ✓ Pong sent

============================================================
✅ Secure channel established!
============================================================

=== Phase 2: Integrity Verification ===
[STEP 1] Waiting for integrity challenge...
  ✓ Challenge received: nonce=12345678
[STEP 2] Loading golden hash...
  ✓ Golden hash loaded (32 bytes)
[STEP 3] Signing (hash || nonce)...
  ✓ Signed with permanent key
[STEP 4] Sending H2T_INTEGRITY_RESPONSE...
  ✓ Sent
[STEP 5] Waiting for T2H_BOOT_OK...
  ✓ Token sent BOOT_OK - integrity verification passed!

============================================================
✅ Integrity verification complete!
============================================================

=== Phase 3: Runtime ===
Entering runtime mode. Press Ctrl+C to exit.
```

---

## Provisioning Instructions

Provisioning is the one-time setup process to establish a trusted relationship between the host and the token. Both sides generate permanent keypairs and securely exchange public keys.

**Important Notes:**
- Provisioning only needs to be done once
- After provisioning, keys are stored persistently
- The HTML UI is the **recommended production method**
- Python methods are provided for testing and automation

### Method 1: HTML UI (Production - Recommended)

The HTML UI provides a user-friendly web interface for provisioning the token. This is the recommended method for production deployments.

#### Prerequisites

- Token firmware flashed and running
- Token WiFi AP is active
- Computer with WiFi capability

#### Step-by-Step Guide

**Step 1: Generate Host Keypair**

First, generate the host's permanent keypair using the standalone provisioning tool:

```bash
cd host/
python -m host.provision --regenerate
```

**Output:**
```
============================================================
MASTR Host Keypair Generation
============================================================

=== Generating Host Permanent Keypair ===
Creating P-256 ECC keypair in TPM2...
✓ Host keypair generated successfully
  Stored at TPM2 handle: 0x81000080

=== Host Public Key (Copy to Token) ===
======================================================================
a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890
1234567890abcdefa1b2c3d4e5f678901234567890abcdefa1b2c3d4e5f67890
======================================================================

Copy the above public key to the token via HTML UI
Token URL: http://192.168.4.1 (when connected to token AP)
```

**Copy the displayed 128-character hex string** (this is your host public key).

**Step 2: Connect to Token WiFi AP**

1. Look for the token's WiFi network in your WiFi settings
   - **SSID format:** `MASTR_TOKEN_<ID>` or similar
   - **Default Password:** Check firmware or documentation
2. Connect to the token's WiFi AP
3. You should receive an IP address (typically 192.168.4.x)

**Step 3: Access the Provisioning Web Interface**

1. Open your web browser
2. Navigate to: **http://192.168.4.1**
3. You should see the **MASTR Dashboard**

**Step 4: Open Provisioning Modal**

1. Click the **"Provision Device"** button on the dashboard
2. A 3-step provisioning wizard will appear

**Step 5: Complete Provisioning Wizard**

**Wizard Step 1: Token Public Key**
- The token's public key will be displayed automatically
- **Copy this 128-character hex string** to your clipboard
- Click **"Next"**

**Wizard Step 2: Host Public Key**
- Paste the **host public key** (from Step 1) into the text area
- Click **"Submit & Verify"**
- Wait for verification (token writes key to ATECC608A)
- Status will show "✓ Host public key accepted"
- Wizard automatically advances to Step 3

**Wizard Step 3: Golden Hash**
- Compute the golden hash of your integrity file:
  ```bash
  # Example: Hash a file
  sha256sum /boot/vmlinuz
  # Or for testing, use default placeholder
  echo -n "h" | sha256sum
  ```
- Paste the **64-character hash** into the text area
- Click **"Complete Provisioning"**
- Status will show "✓ Provisioning complete"

**Step 6: Store Token Public Key on Host**

Return to your terminal and store the token's public key (copied in Step 5):

```bash
python -m host.provision --set-token-pubkey <paste-token-pubkey-here>
```

**Output:**
```
============================================================
Store Token Public Key
============================================================
Storing token public key in TPM2...
  Token pubkey: a1b2c3d4e5f67890...
✓ Token public key stored successfully
  Stored at TPM2 NVRAM: 0x01C00002
```

**Step 7: Verify Provisioning**

```bash
python -m host.provision --verify
```

**Expected Output:**
```
============================================================
Verify Provisioning Status
============================================================

[STEP 1] Checking host permanent keypair...
  ✓ Host keypair exists (TPM2 0x81000080)

[STEP 2] Checking token permanent public key...
  ✓ Token pubkey stored (TPM2 NVRAM 0x01C00002)

============================================================
✅ Provisioning Complete!
============================================================
Host is ready for bootstrap and attestation
Next steps:
  1. Copy bootstrap.py into initramfs
  2. Reboot system
  3. Bootstrap will perform attestation automatically
```

**Step 8: Disconnect and Test**

1. Disconnect from the token WiFi AP
2. Connect the token via USB serial
3. Run the host application:
   ```bash
   python -m host.main /dev/ttyACM0
   ```

#### HTML UI Features

- **Real-time Status:** Shows provisioning status, WiFi config, system stats
- **System Monitoring:** CPU usage, RAM usage, temperature, uptime
- **Network Info:** Connected clients, AP configuration
- **WiFi Configuration:** Claim WiFi with random password generation
- **Bearer Token Authentication:** Secure API access with token-based auth

#### Troubleshooting HTML UI

**Cannot access http://192.168.4.1:**
- Verify you're connected to the token's WiFi AP
- Check your IP address (should be 192.168.4.x)
- Try ping: `ping 192.168.4.1`
- Disable VPN if active

**Token WiFi not visible:**
- Reset token (unplug/replug USB)
- Check firmware is flashed correctly
- Verify ATECC608A is connected properly

**Provisioning wizard fails:**
- Ensure host public key is exactly 128 hex characters
- Ensure golden hash is exactly 64 hex characters
- Check token serial output for errors
- Reset and try again

---

### Method 2: Python CLI Provisioning Tool (Standalone)

The standalone provisioning tool (`provision.py`) provides a command-line interface for managing provisioning independently of the main protocol.

#### Features

- Generate host keypair in TPM2
- Display host public key for token provisioning
- Store token public key in TPM2
- Verify provisioning status
- View current provisioning state

#### Usage

**Show Current Status:**
```bash
python -m host.provision
```

**Output:**
```
============================================================
MASTR Host Provisioning Status
============================================================
TPM2 Host Key Handle: 0x81000080
TPM2 Token Pubkey NV Index: 0x01C00002

=== Host Permanent Keypair ===
✓ Host keypair exists in TPM2
  Public key: a1b2c3d4e5f67890...

=== Token Permanent Public Key ===
⚠ Token pubkey NOT stored in TPM2
Run: python -m host.provision --set-token-pubkey <hex>
```

**Generate Host Keypair:**
```bash
python -m host.provision --regenerate
```

**Display Host Public Key:**
```bash
python -m host.provision --show-pubkey
```

**Store Token Public Key:**
```bash
python -m host.provision --set-token-pubkey <128-char-hex-string>
```

**Display Stored Token Public Key:**
```bash
python -m host.provision --show-token-pubkey
```

**Verify Provisioning Complete:**
```bash
python -m host.provision --verify
```

#### Typical Workflow

```bash
# 1. Generate host keypair
python -m host.provision --regenerate
# → Copy displayed host pubkey

# 2. Provision token via HTML UI with host pubkey
# → Copy token pubkey from HTML UI

# 3. Store token pubkey on host
python -m host.provision --set-token-pubkey <hex-from-token>

# 4. Verify everything is set up
python -m host.provision --verify
```

#### What Gets Stored

**Host (TPM2):**
- Host permanent private key → TPM2 persistent handle `0x81000080`
- Token permanent public key → TPM2 NVRAM index `0x01C00002`

**Token (ATECC608A):**
- Token permanent private key → Slot 0 (hardware-protected, never leaves chip)
- Host permanent public key → Slot 8
- Golden hash → Slot 8 Block 2

---

### Method 3: Python API Client (Debug/Testing)

This method uses the token's HTTP API for provisioning programmatically. **Use HTML UI instead for production.**

#### When to Use

- Automated testing
- CI/CD pipelines
- Scripted deployments
- Development/debugging

#### Prerequisites

- Token WiFi AP active
- Connected to token WiFi network (192.168.4.x)
- Bearer token for API authentication

#### Usage

```bash
# Connect token via USB serial
python -m host.main /dev/ttyACM0 --provision

# This will:
# 1. Generate host keypair
# 2. Use HTTP API to provision token
# 3. Store token pubkey locally
# 4. Proceed with attestation
```

#### How It Works

1. **Generate Bearer Token:** Obtains authentication token from `/api/auth/generate-token`
2. **Get Token Info:** Fetches token public key from `/api/provision/token_info`
3. **Submit Host Pubkey:** POSTs host public key to `/api/provision/host_pubkey`
4. **Poll Status:** Waits for ATECC608A write completion
5. **Submit Golden Hash:** POSTs golden hash to `/api/provision/golden_hash`
6. **Poll Status:** Waits for final write completion

#### API Endpoints Used

- `POST /api/auth/generate-token` - Get bearer token
- `GET /api/provision/token_info` - Get token public key
- `POST /api/provision/host_pubkey` - Submit host public key (128 hex chars)
- `GET /api/provision/host_pubkey/status` - Check write status
- `POST /api/provision/golden_hash` - Submit golden hash (64 hex chars)
- `GET /api/provision/golden_hash/status` - Check write status

#### Limitations

- **Debug only:** Not recommended for production
- **Serial required:** Must have serial connection
- **No confirmation:** Automatically proceeds (HTML UI allows review)
- **Less user-friendly:** No visual feedback

---

### Method 4: Serial Protocol (Legacy/Debug)

This method uses the debug serial protocol for provisioning. **Deprecated and will be removed.**

#### When to Use

- **DO NOT USE** for production
- Only for firmware testing
- Debugging protocol implementation

#### Usage

```bash
python -m host.main /dev/ttyACM0 --debug-override-provision
```

#### How It Works

Uses debug message types over serial:
- `0xFB: H2T_DEBUG_SET_HOST_PUBKEY` - Send host public key
- `0xFA: T2H_DEBUG_GET_TOKEN_PUBKEY` - Request token public key
- `0xF9: H2T_DEBUG_SET_GOLDEN_HASH` - Send golden hash

#### Why Deprecated

- Bypasses WiFi provisioning workflow
- Not suitable for production deployment
- Requires direct serial access
- Conflicts with production protocol flow
- Will be removed when `host/main.py` becomes production script

**Use HTML UI or standalone provisioning tool instead.**

---

## Testing

The project includes comprehensive unit tests using the Unity testing framework.

### Running Unit Tests

```bash
# Navigate to test directory
cd test
mkdir build
cd build

# Configure tests
cmake ..

# Build tests
make

# Run all tests
ctest

# Or run test executable directly
./test_runner
```

**Run Specific Test Suites:**
```bash
# Build individual test suites
make test_crypto
make test_protocol
make test_serial

# Run specific test
./test_crypto
```

### Generating Coverage Reports

```bash
# From test/build directory
cd test

# Run coverage script
./generate_coverage.sh

# View coverage report
firefox coverage/index.html
# Or
xdg-open coverage/index.html
```

**Manual Coverage Generation:**
```bash
# Build with coverage flags
cmake .. -DCMAKE_C_FLAGS="--coverage"
make

# Run tests
ctest

# Generate coverage report
lcov --capture --directory . --output-file coverage.info
lcov --remove coverage.info '/usr/*' --output-file coverage.info
genhtml coverage.info --output-directory coverage
```

### Interpreting Test Results

**Successful Test Run:**
```
Test project /path/to/MASTR-NEW/test/build
    Start 1: test_runner
1/1 Test #1: test_runner ......................   Passed    0.05 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) =   0.06 sec
```

**Failed Test Example:**
```
test/test_crypto.c:45:test_ecdh_key_generation:FAIL: Expected 0, Was -1

-----------------------
3 Tests 1 Failures 0 Ignored
FAIL
```

**Coverage Metrics:**
- **Lines:** Percentage of code lines executed
- **Functions:** Percentage of functions called
- **Branches:** Percentage of conditional branches tested

**Good Coverage Targets:**
- Lines: > 80%
- Functions: > 90%
- Branches: > 70%

---

## Troubleshooting

### Serial Port Issues

#### Problem: "Failed to connect to /dev/ttyACM0"

**Causes:**
- Device not plugged in
- Wrong port name
- Permission denied (Linux)
- Port in use by another application

**Solutions:**

**Linux:**
```bash
# List available serial ports
ls -l /dev/ttyACM* /dev/ttyUSB*

# Check device permissions
ls -l /dev/ttyACM0

# Add user to dialout group (one-time setup)
sudo usermod -a -G dialout $USER
# Log out and log back in for changes to take effect

# Kill processes using the port
sudo lsof /dev/ttyACM0
sudo kill <PID>
```

**macOS:**
```bash
# List available ports
ls -l /dev/tty.usbmodem*
ls -l /dev/cu.usbmodem*

# Use the tty.* variant
python -m host.main /dev/tty.usbmodem14101
```

**Windows:**
```cmd
# Open Device Manager
devmgmt.msc

# Look under "Ports (COM & LPT)"
# Note the COM port (e.g., COM3, COM4)

# Run with correct port
python -m host.main COM3
```

#### Problem: "Serial port permission denied"

**Linux Solution:**
```bash
# Temporary (until reboot)
sudo chmod 666 /dev/ttyACM0

# Permanent (add user to group)
sudo usermod -a -G dialout $USER
# Log out and back in
```

---

### Provisioning Failures

#### Problem: "Host keypair already exists"

**Cause:** Attempting to generate keypair when one already exists

**Solution:**
```bash
# Force regeneration
python -m host.provision --regenerate

# Or delete existing keys first
# TPM2:
tpm2_evictcontrol -C o -c 0x81000080

# File-based:
rm host_permanent_privkey.pem host_permanent_pubkey.bin
```

#### Problem: "Token pubkey not found"

**Cause:** Token public key was not stored on host

**Solution:**
```bash
# Ensure you completed provisioning via HTML UI
# Then store the token pubkey
python -m host.provision --set-token-pubkey <128-char-hex>
```

#### Problem: "Invalid pubkey length"

**Cause:** Public key hex string is not exactly 128 characters (64 bytes)

**Solution:**
- Verify you copied the entire key
- Remove any spaces or newlines
- Public keys are always 64 bytes = 128 hex characters

#### Problem: "Golden hash write failed"

**Cause:** ATECC608A write error or invalid hash format

**Solutions:**
```bash
# Verify hash is 64 hex characters (32 bytes)
echo "hash" | wc -c    # Should be 65 (64 + newline)

# Try again with correct format
# Hash must be SHA-256 output (32 bytes)
sha256sum /boot/vmlinuz | awk '{print $1}'
```

---

### Protocol Errors

#### Problem: "Timeout waiting for T2H_ECDH_SHARE"

**Causes:**
- Token not responding
- Token in wrong state
- Firmware crash
- Wrong baud rate

**Solutions:**
```bash
# Reset token (unplug and replug USB)

# Try different baud rate
python -m host.main /dev/ttyACM0 -b 9600

# Check token firmware is running
# Look for WiFi AP or serial output

# Reflash firmware if necessary
```

#### Problem: "Signature verification failed"

**Causes:**
- Mismatched keys between host and token
- Corrupted key files
- Token provisioned with different host key

**Solutions:**
```bash
# Check provisioning status
python -m host.provision --verify

# If keys are mismatched, re-provision from scratch
# 1. Reset token (reflash firmware or use HTML UI to clear)
# 2. Regenerate host keypair
python -m host.provision --regenerate

# 3. Re-provision token via HTML UI
# 4. Store token pubkey
python -m host.provision --set-token-pubkey <new-token-key>
```

#### Problem: "Decryption failed / MAC verification failed"

**Causes:**
- Session key mismatch
- Corrupted encrypted message
- Wrong encryption parameters

**Solutions:**
```bash
# Run with verbose mode to see key derivation
python -m host.main /dev/ttyACM0 -v

# Reset and re-establish session
# (unplug/replug token)

# If persistent, check firmware crypto implementation
```

#### Problem: "T2H_INTEGRITY_FAIL_HALT received"

**Causes:**
- Golden hash mismatch
- Host firmware modified
- Incorrect integrity file

**Solutions:**
```bash
# Verify golden hash matches current file
sha256sum /boot/vmlinuz

# Update golden hash on token via HTML UI
# Or re-provision with correct hash

# For testing, use placeholder hash
# (see firmware documentation)
```

---

### TPM2 Issues

#### Problem: "Failed to initialize TPM2 crypto"

**Causes:**
- TPM2 device not available
- Missing permissions
- tpm2-pytss not installed

**Solutions:**
```bash
# Check TPM2 device exists
ls -l /dev/tpm*

# Check user is in tss group
groups
# Should show: tss

# Add user to tss group
sudo usermod -a -G tss $USER
# Log out and log back in

# Install tpm2-pytss
# Arch Linux:
sudo pacman -S python-tpm2-pytss

# Ubuntu/Debian:
sudo apt-get install python3-tpm2-pytss

# Verify TPM2 works
tpm2_getcap properties-fixed
```

#### Problem: "TPM2 key already exists at handle"

**Cause:** Previous key exists at persistent handle

**Solutions:**
```bash
# Remove existing persistent key
tpm2_evictcontrol -C o -c 0x81000080

# Remove existing NVRAM
tpm2_nvundefine 0x01C00002 -C o

# Or use --provision flag to regenerate
python -m host.provision --regenerate
```

#### Problem: "TPM2 NVRAM index already defined"

**Cause:** NVRAM space already allocated

**Solution:**
```bash
# Undefine existing NVRAM
tpm2_nvundefine 0x01C00002 -C o

# Verify it's gone
tpm2_nvreadpublic 0x01C00002
# Should fail with "handle does not exist"
```

---

## Project Structure

```
MASTR-NEW/
├── src/                          # Firmware source code (C)
│   ├── main.c                    # FreeRTOS initialization, app lifecycle
│   ├── protocol.c                # Protocol state machine
│   ├── serial.c                  # UART communication & framing
│   ├── crypto.c                  # ATECC608A crypto operations
│   ├── net/
│   │   ├── api/
│   │   │   └── api.c             # HTTP API endpoints
│   │   ├── wifi_ap.c             # WiFi AP management
│   │   └── http/
│   │       └── http_server.c     # HTTP server implementation
│   └── ...
├── include/                      # Firmware header files
│   ├── protocol.h
│   ├── serial.h
│   ├── crypto.h
│   └── ...
├── host/                         # Python host implementation
│   ├── main.py                   # MASTRHost state machine
│   ├── provision.py              # Standalone provisioning tool
│   ├── serial_handler.py         # Serial communication
│   ├── protocol.py               # Message type definitions
│   ├── crypto.py                 # NaiveCrypto (file-based)
│   ├── tpm2_crypto.py            # TPM2Crypto (hardware-backed)
│   ├── parser.py                 # Frame parsing
│   ├── logger.py                 # Centralized logging
│   ├── api_client.py             # HTTP API client
│   └── requirements.txt          # Python dependencies
├── test/                         # Unit tests (Unity framework)
│   ├── test_runner.c             # Test runner
│   ├── test_protocol.c           # Protocol tests
│   ├── test_crypto.c             # Crypto tests
│   ├── test_serial.c             # Serial tests
│   └── mocks/                    # Mock implementations
├── docs/                         # Documentation & diagrams
│   ├── Embedded-pairing-process.drawio (1).png
│   ├── Secure Channel Phase 2 embed.drawio.png
│   ├── Integrity Attest Phase 3 embed.drawio.png
│   ├── provisioning_flow.md
│   └── ap_http_architecture.md
├── index.html                    # Provisioning web UI (standalone)
├── CMakeLists.txt                # Firmware build configuration
├── README.md                     # This file
├── PROVISIONING.md               # Detailed provisioning guide
├── QUICK_START_TPM2.md           # TPM2 quick start guide
└── LICENSE.TXT                   # License information
```

---

## Additional Resources

- **[PROVISIONING.md](./PROVISIONING.md)** - Detailed provisioning guide
- **[QUICK_START_TPM2.md](./QUICK_START_TPM2.md)** - TPM2 setup and usage
- **[host/README.md](./host/README.md)** - Python host implementation details
- **[host/ARCHITECTURE.md](./host/ARCHITECTURE.md)** - Detailed architecture documentation
- **[docs/provisioning_flow.md](./docs/provisioning_flow.md)** - Provisioning flow diagrams
- **[docs/ap_http_architecture.md](./docs/ap_http_architecture.md)** - WiFi AP and HTTP architecture

**External Resources:**
- [Raspberry Pi Pico SDK Documentation](https://raspberrypi.github.io/pico-sdk-doxygen/)
- [ATECC608A Datasheet](https://www.microchip.com/wwwproducts/en/ATECC608A)
- [FreeRTOS Documentation](https://www.freertos.org/Documentation/RTOS_book.html)
- [TPM2 Software Stack](https://github.com/tpm2-software/tpm2-pytss)

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes**
4. **Add tests** if applicable
5. **Ensure tests pass** (`ctest` in test/build)
6. **Follow code style:**
   - **C code:** Barr-C Embedded Standards
     - Global variables: `g_variable_name`
     - Module static: `m_variable_name`
     - Functions: `snake_case`
     - Macros: `UPPER_CASE`
   - **Python code:** PEP 8
     - Use type hints
     - Add docstrings
     - Use Logger class for output
7. **Commit your changes** (`git commit -m 'Add amazing feature'`)
8. **Push to the branch** (`git push origin feature/amazing-feature`)
9. **Open a Pull Request**

---

## License

This project is licensed under the BSD 3-Clause License as specified in [LICENSE.TXT](./LICENSE.TXT).

---
**Last Updated:** 2025-11-23
**Version:** 3.0 (Production Ready with Full Provisioning Support)

**Questions or Issues?** Open an issue on the project repository or consult the documentation in the `docs/` directory.
