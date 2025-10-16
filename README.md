# MASTR: Mutual Attested Secure Token for Robotics

MASTR is a security-focused project designed to establish a secure communication channel between a host system and a hardware token. It utilizes a three-phase protocol to ensure mutual attestation, secure channel establishment, and runtime integrity verification.

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

## Building and Running the Project

### Prerequisites

*   Raspberry Pi Pico SDK
*   CMake (version 3.13 or later)
*   ARM GCC Compiler

### Build Instructions

1.  **Create a build directory:**

    ```bash
    mkdir build
    cd build
    ```

2.  **Configure for your board:**

    *   **For Raspberry Pi Pico (RP2040):**

        ```bash
        cmake .. -DPICO_BOARD=pico
        ```

    *   **For Raspberry Pi Pico W (RP2040 with WiFi):**

        ```bash
        cmake .. -DPICO_BOARD=picow
        ```

    *   **For a generic RP2350 board:**

        ```bash
        cmake .. -DPICO_PLATFORM=rp2350
        ```

3.  **Build the project:**

    ```bash
    make
    ```

### Running

1.  Connect your Pico board to your computer while holding the `BOOTSEL` button.
2.  Drag and drop the `mastr.uf2` file from the `build` directory onto the `RPI-RP2` mass storage device.

## Testing

The project uses the Unity test framework. The tests are located in the `test` directory.

### Running the Tests

1.  Navigate to the build directory: `cd build`
2.  Build the test runner: `make test_runner`
3.  Run the tests: `ctest`
