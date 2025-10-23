# MASTR Host Communication Library

**Reference implementation** for communicating with the MASTR Token device over serial (USB CDC).

## Overview

The MASTR protocol enables secure communication between a host system and a hardware security token (RP2040 + ATECC608A). This Python library implements:

- **Protocol Parser**: Byte-stuffing frame parser with checksum validation
- **Serial Handler**: Robust serial communication with auto-reconnection
- **Message Types**: Complete enumeration of all protocol messages
- **Test Application**: Interactive command-line tool for testing

## Features

- **Protocol Parsing**: Handles byte-stuffing, frame boundaries, and checksum verification
- **Debug Message Support**: Automatically detects and displays DEBUG messages from the token
- **Separation of Concerns**: Clean OOP architecture with distinct protocol, parser, and serial handler layers
- **Real-time Display**: Shows received frames with hex dumps and decoded payloads
- **Error Handling**: Comprehensive error reporting for protocol violations and checksum failures
- **Auto-reconnection**: Automatically reconnects when device is disconnected/reconnected
- **Interactive Commands**: Send test messages to the device

## Usage

### As a Test Application

Run the interactive test receiver:

```bash
# Basic usage
python -m host.main /dev/ttyACM0

# With verbose output
python -m host.main /dev/ttyACM0 -v

# With raw byte debugging
python -m host.main /dev/ttyACM0 -d

# Custom baud rate
python -m host.main /dev/ttyACM0 -b 115200

# On Windows
python -m host.main COM3
```

**Interactive Commands:**
- `r` - Request random number from ATECC608A
- `q` - Quit application

### As a Library

```python
from host.serial_handler import SerialHandler
from host.protocol import MessageType, Frame

def on_frame(frame: Frame):
    if frame.is_debug:
        print(f"DEBUG: {frame.debug_text}")
    else:
        print(f"Received: {frame.msg_type.name}, payload: {len(frame.payload)} bytes")

handler = SerialHandler(
    port="/dev/ttyACM0",
    baudrate=115200,
    on_frame=on_frame
)

handler.connect()
handler.start()

# Send a message
handler.send_frame(MessageType.H2T_TEST_RANDOM_REQUEST)

# ... later ...
handler.stop()
handler.disconnect()
```

## Architecture

### Components

1. **protocol.py**: Protocol definitions (message types, constants, frame structure)
2. **parser.py**: Stateful frame parser with byte-stuffing support
3. **serial_handler.py**: Serial communication manager with background thread
4. **main.py**: Application entry point and frame display logic

## Protocol Details

### Frame Structure

```
[SOF] [Type] [Length_LSB] [Length_MSB] [Payload...] [Checksum] [EOF]
```

- **SOF**: Start of Frame (0x7F)
- **Type**: Message type (1 byte)
- **Length**: Payload length in bytes (2 bytes, little-endian)
- **Payload**: Variable length (0-256 bytes)
- **Checksum**: XOR of all bytes from Type to end of Payload (1 byte)
- **EOF**: End of Frame (0x7E)

### Byte Stuffing

Special bytes are escaped during transmission:
- `0x7F` (SOF) → `0x7D 0x5F`
- `0x7E` (EOF) → `0x7D 0x5E`
- `0x7D` (ESC) → `0x7D 0x5D`

### Message Types

#### Class 0: System Control (0x00-0x0F)
- `T2H_ERROR (0x00)`: Error message from token
- `T2H_NACK (0x01)`: Negative acknowledgment
- `H2T_BOOT_OK_ACK (0x02)`: Host acknowledges boot authorization

#### Phase 1: ECDH Key Exchange (0x20-0x2F)
- `H2T_ECDH_SHARE (0x20)`: Host ephemeral public key
- `T2H_ECDH_SHARE (0x21)`: Token ephemeral public key
- `H2T_CHANNEL_VERIFY_REQUEST (0x22)`: Encrypted ping
- `T2H_CHANNEL_VERIFY_RESPONSE (0x23)`: Encrypted pong

#### Phase 2: Integrity Verification (0x30-0x3F)
- `T2H_INTEGRITY_CHALLENGE (0x30)`: Challenge with nonce
- `H2T_INTEGRITY_RESPONSE (0x31)`: Hash + signature response
- `T2H_BOOT_OK (0x32)`: Integrity check passed
- `T2H_INTEGRITY_FAIL_HALT (0x33)`: Integrity check failed

#### Runtime: Heartbeat (0x40-0x4F)
- `H2T_HEARTBEAT (0x40)`: Periodic heartbeat from host
- `T2H_HEARTBEAT_ACK (0x41)`: Token acknowledges heartbeat

#### Testing & Debug (0xFC-0xFE)
- `DEBUG_MSG (0xFE)`: Debug text message (UTF-8 string)
- `H2T_TEST_RANDOM_REQUEST (0xFD)`: Request random number
- `T2H_TEST_RANDOM_RESPONSE (0xFC)`: Random number response (32 bytes)

## Output Example

```
MASTR Host Receiver Test
Waiting for device at /dev/ttyACM0 (will retry indefinitely)...
Commands: 'r' = request random number, 'q' = quit

Connected to /dev/ttyACM0 at 115200 baud!
Listening for frames...

[DEBUG FROM PICO] Board info: RP2040, Serial: E66298B013579F3F
[DEBUG FROM PICO] ATECC608A initialized successfully

[Sending] H2T_TEST_RANDOM_REQUEST
[Sent] Random number request sent successfully

[DEBUG FROM PICO] Frame validated: type=0xFD, payload_len=0
[DEBUG FROM PICO] Received message type: 0xFD, length: 0
[DEBUG FROM PICO] Handler: H2T_TEST_RANDOM_REQUEST - Generating random number...
[DEBUG FROM PICO] Generated 32 bytes of random data from ATECC608

[Frame #1]
  Type: T2H_TEST_RANDOM_RESPONSE (0xFC)
  Payload Length: 32 bytes
  [VERIFICATION] Random data (for comparison):
    4D 39 AC 2E 93 5A 8D A6 EE 51 E6 85 AA B5 55 F6 4E 89 CD 7C 31 1E BA 74 EF 42 B1 80 6E AC AA 11
  Payload (hex):
    0000: 4D 39 AC 2E 93 5A 8D A6 EE 51 E6 85 AA B5 55 F6  M9...Z...Q....U.
    0010: 4E 89 CD 7C 31 1E BA 74 EF 42 B1 80 6E AC AA 11  N..|1..t.B..n...
```

## Error Handling

The library handles:
- **Checksum errors**: Invalid frame checksums are rejected
- **Protocol errors**: Malformed frames trigger parser reset
- **Serial errors**: Auto-reconnection on disconnect
- **Timeout errors**: Configurable connection retry logic

## Testing

This receiver is designed for physical unit testing of the MASTR token device. It provides:

- Colored output for different message types (success, error, debug, etc.)
- Hex dump of binary payloads with ASCII preview
- Frame counting and statistics
- Raw byte debugging mode (`-d` flag)

## Development

### Adding New Message Types

1. Add to `protocol.py`:
```python
class MessageType(IntEnum):
    MY_NEW_MESSAGE = 0xAB
```

2. Add to C header `include/protocol.h`:
```c
typedef enum {
    // ... existing types ...
    MY_NEW_MESSAGE = 0xAB,
} message_type_t;
```

3. Add handler in `src/protocol.c`:
```c
case MY_NEW_MESSAGE:
    // Handle message
    break;
```

### Debugging

Enable raw byte output to see all serial data:
```bash
python -m host.main /dev/ttyACM0 -d
```

This shows:
- All bytes received on the wire
- Frame parsing details
- Checksum validation results

## License

See LICENSE.TXT in the project root.
