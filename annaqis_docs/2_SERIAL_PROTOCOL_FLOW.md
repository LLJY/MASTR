# MASTR Serial Protocol Flow - How the Listener Works

## Overview

The MASTR token uses event-driven serial communication over USB CDC (USB Communication Device Class). The serial listener is **non-blocking** and uses FreeRTOS task notifications for efficient CPU usage.

---

## Serial Architecture

### USB Communication Stack
```
┌────────────────────────────────┐
│ Host Machine                   │
│ (sends protocol messages)      │
└────────────────┬───────────────┘
                 │ USB CDC
                 ↓
┌────────────────────────────────┐
│ Raspberry Pi Pico W/RP2350     │
├────────────────────────────────┤
│ USB CDC RX (TinyUSB)           │
│     ↓                          │
│ tud_cdc_rx_cb() [ISR]          │
│     ↓                          │
│ vTaskNotifyGiveFromISR()       │
│     ↓                          │
│ FreeRTOS Scheduler             │
│     ↓                          │
│ serial_task (wakes up)         │
│     ↓                          │
│ rx_buffer_fill()               │
│ process_serial_data()          │
│ handle_validated_message()     │
│     ↓                          │
│ Protocol State Machine         │
└────────────────────────────────┘
```

### Key Components

1. **USB Interrupt Handler** - Wakes serial task on data arrival
2. **Ring Buffer** - Temporary storage for incoming bytes
3. **Frame Parser** - Decodes frame format with escape sequences
4. **Message Validator** - Checksum and format validation
5. **Protocol Handler** - Routes messages to protocol state machine

---

## Startup Sequence

### 1. Initialization (main.c)

```c
int main() {
    // Initialize USB
    stdio_init_all();
    
    // Initialize crypto (ATECC608A)
    atcab_init(&cfg);
    crypt_init();
    
    // Create serial task
    xTaskCreate(
        serial_task,
        "Serial",
        DEFAULT_STACK_SIZE,
        NULL,
        configMAX_PRIORITIES - 6,  // Priority 26
        &serial_task_handle
    );
    
    // Initialize serial subsystem with interrupt handler
    serial_init(serial_task_handle);
    
    // Initialize protocol state
    protocol_state.current_state = H2T_ECDH_SHARE;  // 0x20
    protocol_state.is_encrypted = false;
    
    // Start FreeRTOS scheduler
    vTaskStartScheduler();
}
```

**Order is critical**: 
1. Create task FIRST
2. Initialize serial SECOND (stores task handle for interrupt)
3. Start scheduler LAST

### 2. Serial Subsystem Initialization (serial.c)

```c
void serial_init(TaskHandle_t task_handle) {
    // Store task handle for ISR to use
    serial_task_handle = task_handle;
    
    // Set USB interrupt priority for FreeRTOS compatibility
    // Must be >= configMAX_SYSCALL_INTERRUPT_PRIORITY
    irq_set_priority(USBCTRL_IRQ, configMAX_SYSCALL_INTERRUPT_PRIORITY + 0x20);
}
```

This registers the interrupt handler and stores the task handle.

### 3. Serial Task Startup (serial.c)

```c
void serial_task(void *params) {
    (void)params;
    
    while (true) {
        process_serial_data();
        // Blocks here waiting for USB data
    }
}
```

The task blocks on **first call** to `process_serial_data()`.

---

## Event Flow: USB Data Arrival

### Step 1: USB Interrupt (Hardware Interrupt Context)

```
USB Hardware Detects Data
    ↓
CPU Enters Interrupt Handler
    ↓
tud_cdc_rx_cb() [interrupt context]
    {
        BaseType_t xHigherPriorityTaskWoken = pdFALSE;
        
        if (serial_task_handle != NULL) {
            vTaskNotifyGiveFromISR(serial_task_handle, 
                                  &xHigherPriorityTaskWoken);
            portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
        }
    }
    ↓
ISR Returns
```

**Key Points**:
- `vTaskNotifyGiveFromISR()` increments task notification count
- `portYIELD_FROM_ISR()` allows context switch if task is higher priority
- This is **very fast** (~10-50 CPU cycles)

### Step 2: FreeRTOS Context Switch

```
FreeRTOS Scheduler Checks:
    "Is serial_task higher priority than current task?"
    ├─ If YES: Switch immediately to serial_task
    └─ If NO: Switch when current task blocks/yields
```

### Step 3: Serial Task Resumes (FreeRTOS Context)

```c
void process_serial_data() {
    // BLOCKING CALL - waits here until ISR wakes task
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    
    // ISR fired! Task wakes here
    rx_buffer_fill();  // Copy data from USB CDC to ring buffer
    
    // Process all available bytes
    uint8_t c;
    while (rx_buffer_get(&c)) {
        // Parse frame byte-by-byte
    }
}
```

**Key Points**:
- `ulTaskNotifyTake()` is a **blocking wait**, not polling
- Task is suspended while waiting (0% CPU)
- ISR sets notification counter, task reads it
- Counting notification = multiple ISRs between polls

### Step 4: Frame Processing

```
Parse Incoming Bytes:
    ├─ Detect frame start (FLAG = 0x7E)
    ├─ Handle escape sequences (ESCAPE = 0x7D)
    ├─ Unstuff escaped bytes
    ├─ Accumulate into frame_buffer
    └─ Detect frame end (FLAG = 0x7E)
         ↓
    process_complete_frame()
         ├─ Validate checksum
         ├─ Extract message type & payload
         ├─ Decrypt if encrypted
         └─ Call handle_validated_message()
             ↓
         Protocol State Machine (protocol.c)
             └─ Execute handler for message type
```

### Step 5: Back to Waiting

```c
// process_serial_data() loop continues
// If more data in buffer: Process it
// If buffer empty: Loop back to ulTaskNotifyTake()
//    ↓
// Task blocks again, waiting for next ISR
// Returns to event-driven waiting
```

---

## Frame Format

### Byte Stuffing Protocol

```
Frame Format: [FLAG] [Data...] [FLAG]

FLAG = 0x7E
ESCAPE = 0x7D
ESCAPE_FLAG = 0x5E  (0x7E XOR 0x20)
ESCAPE_ESCAPE = 0x5D (0x7D XOR 0x20)

Transmission:
Original byte 0x7E → Sent as: 0x7D 0x5E
Original byte 0x7D → Sent as: 0x7D 0x5D
```

### Full Message Structure

```
┌─────────────┬──────┬─────────────┬──────────┬──────┐
│ FLAG (0x7E) │ Type │ Payload Len │ Payload  │ Chk  │ FLAG (0x7E)
│ 1 byte      │1 byte│ 2 bytes     │ Variable │1 byte│ 1 byte
└─────────────┴──────┴─────────────┴──────────┴──────┘
```

### Example: H2T_ECDH_SHARE Message (128 bytes payload)

```
Raw (before escape):    7E 20 00 80 [128 bytes pubkey+sig] XX 7E
Transmitted:            7E 20 00 80 [escaped data] XX 7E
Received:               7E 20 00 80 [unescaped in buffer] XX 7E
```

---

## Message Encryption

### When Encryption Is Active

From state 0x21 onward (`is_encrypted = true`):

```c
// Receiving encrypted message:
uint8_t encrypted_payload[payload_len];
memcpy(encrypted_payload, frame_payload, payload_len);

// Decrypt with session key
uint8_t decrypted_payload[payload_len];
mbedtls_aes_crypt_ecb(&aes_ctx, 
                      MBEDTLS_AES_DECRYPT,
                      encrypted_payload,
                      decrypted_payload);

// Call handler with decrypted data
handle_validated_message(msg_type, decrypted_payload, payload_len);
```

### Sending Messages

```c
void send_message(uint8_t msg_type, uint8_t *payload, uint16_t len) {
    // Encrypt payload if needed
    if (protocol_state.is_encrypted) {
        mbedtls_aes_crypt_ecb(&aes_ctx,
                              MBEDTLS_AES_ENCRYPT,
                              payload,
                              payload);  // In-place encryption
    }
    
    // Build frame with byte stuffing
    // Transmit via USB CDC
    tud_cdc_write(frame_buffer, frame_size);
    tud_cdc_write_flush();
}
```

---

## Ring Buffer Management

### Ring Buffer Structure

```c
#define RX_BUFFER_SIZE 512

static uint8_t rx_buffer[RX_BUFFER_SIZE];
static volatile uint16_t rx_write_idx = 0;  // ISR writes here
static volatile uint16_t rx_read_idx = 0;   // Task reads here
```

### Write (from ISR)

```c
void tud_cdc_rx_cb(uint8_t itf) {
    while (tud_cdc_available()) {
        uint16_t next_write = (rx_write_idx + 1) % RX_BUFFER_SIZE;
        
        if (next_write == rx_read_idx) {
            // Buffer full, drop data
            break;
        }
        
        int c = tud_cdc_read_char();
        rx_buffer[rx_write_idx] = (uint8_t)c;
        rx_write_idx = next_write;
    }
}
```

### Read (from Task)

```c
static inline bool rx_buffer_get(uint8_t *byte) {
    if (rx_read_idx == rx_write_idx) {
        return false;  // Empty
    }
    
    *byte = rx_buffer[rx_read_idx];
    rx_read_idx = (rx_read_idx + 1) % RX_BUFFER_SIZE;
    return true;
}
```

### Advantages

✅ Lock-free (no mutexes needed)  
✅ ISR-safe (only index updates are atomic)  
✅ Circular buffer (efficient memory use)  
✅ Works with counting notifications  

---

## Complete Message Flow Example

### Scenario: Host Sends H2T_ECDH_SHARE

```
Host Sends:
    7E 20 00 80 [128 bytes] XX 7E
         │      │
         └──────┤ Message type: 0x20 (H2T_ECDH_SHARE)
                └─ Payload length: 0x0080 (128 bytes)

Token Receives:
    
    [1] USB ISR fires
        ├─ Copy 0x7E → rx_buffer[0]
        ├─ Copy 0x20 → rx_buffer[1]
        ├─ Copy 0x00 → rx_buffer[2]
        ├─ Copy 0x80 → rx_buffer[3]
        ├─ Copy 128 payload bytes
        ├─ Copy checksum
        ├─ Copy 0x7E → final position
        └─ Call vTaskNotifyGiveFromISR(serial_task_handle)
    
    [2] FreeRTOS wakes serial_task
        
    [3] process_serial_data() resumes
        ├─ rx_buffer_fill() (data already there, just update indices)
        ├─ Parse bytes:
        │  ├─ 0x7E → start of frame
        │  ├─ 0x20 → message type
        │  ├─ 0x0080 → payload length
        │  ├─ 128 bytes → payload
        │  ├─ XX → checksum
        │  └─ 0x7E → end of frame
        │
        └─ process_complete_frame()
             ├─ Validate checksum ✓
             ├─ Extract: msg_type=0x20, payload=128 bytes
             ├─ NOT encrypted (state 0x20), so no decryption
             └─ Call handle_validated_message(0x20, payload, 128)
    
    [4] Protocol handler processes ECDH_SHARE
        ├─ Verify host signature ✓
        ├─ Generate ephemeral key
        ├─ Compute shared secret
        ├─ Derive session key
        ├─ Encrypt and send T2H_ECDH_SHARE response
        └─ Transition to state 0x21

    [5] serial_task loops back to process_serial_data()
        └─ Blocks again on ulTaskNotifyTake()
```

---

## Task Priority & Responsiveness

### Serial Task Priority: 26 (HIGH)

```
FreeRTOS Priority Hierarchy:
    31 (MAX-1):  Timer (system)
    27:          Watchdog (safety)
    26:          Serial ← PROTOCOL PROCESSING
    ...
    10:          Web server
    ...
    0:           Idle
```

### Why Priority 26?

- **Protocol messages are time-sensitive**: If serial task is delayed, protocol timeouts may trigger
- **Higher than HTTP (10)**: HTTP requests don't block protocol
- **Just below watchdog (27)**: System safety takes precedence
- **ISR always preempts**: USB interrupt fires regardless of priority

### Responsiveness Guarantees

```
USB Data Arrives
    ↓ (ISR, ~10-50 cycles)
serial_task Wakes
    ↓ (context switch, ~100-200 cycles)
process_serial_data() Executes
    ↓
Message Processed
    ↓
Protocol Handler Runs

Total Latency: ~1-2 milliseconds (usually)
```

---

## Debug Output

All debug messages go through the protocol:

```c
void print_dbg(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    char buffer[256];
    vsnprintf(buffer, sizeof(buffer), format, args);
    
    #ifdef DEBUG
    send_message(DEBUG_MSG, (uint8_t *)buffer, strlen(buffer));
    #endif
    
    va_end(args);
}
```

**Note**: Debug output is **encrypted** when `is_encrypted = true`

---

## Error Handling

### Invalid Frame

```
Frame validation fails (bad checksum)
    ↓
Log error message
    ↓
Discard frame
    ↓
Continue waiting for next frame
```

### Invalid Message Type

```
Message type not recognized
    ↓
Handle as error (send T2H_ERROR or shutdown)
    ↓
Continue waiting
```

### Decryption Failure

```
Message claims to be encrypted but is corrupted
    ↓
Log error
    ↓
Send T2H_ERROR
    ↓
May trigger protocol error handling
```

---

## Monitoring & Debugging

### Serial Output Example

```
MASTR - Mutual Attested Secure Token for Robotics
Board: pico_w
SoC: RP2350 with Wireless Interface Package (CYW43439) or WiFi on board
WiFi support: Enabled
Watchdog task started
WiFi background task started
HTTP server task started
WiFi AP started: SSID=MASTR-Token (192.168.4.1)

Received message type: 0x20, length: 128
Handler: H2T_ECDH_SHARE started
Generated new ephemeral keypair
Sent T2H_ECDH_SHARE (host-initiated ECDH)
Session established - entering runtime (timeout: 30000ms)
```

### Protocol Timing

```
T+0ms:  Host sends H2T_ECDH_SHARE
T+1ms:  USB ISR fires
T+2ms:  serial_task wakes
T+3ms:  Frame validated
T+5ms:  ECDH computation complete
T+6ms:  T2H_ECDH_SHARE sent
T+10ms: Host receives response
```

---

## Summary

✅ **Event-driven**: No polling, tasks wait on interrupts  
✅ **Non-blocking**: Serial task doesn't hog CPU  
✅ **Responsive**: Protocol messages processed quickly  
✅ **Encrypted**: Messages encrypted from state 0x21 onward  
✅ **Robust**: Ring buffer handles burst data  
✅ **Efficient**: Ring buffer is lock-free and ISR-safe  

The serial listener is a model of FreeRTOS + hardware integration, demonstrating proper use of task notifications for interrupt-driven communication.
