# WiFi Integration Architecture

Complete technical architecture for integrating WiFi Access Point with MASTR's serial protocol using FreeRTOS.

## Problem Statement

Your WiFi AP isn't working despite using `CYW43_ARCH_THREADSAFE_BACKGROUND` because:

1. **Missing WiFi Background Task**: CYW43 driver requires a task to run every 50-100ms for:
   - Processing WiFi events
   - Handling DHCP/DNS
   - Managing packet transmit/receive buffers
   - Timeout handling

2. **Not a Serial Blocking Issue**: Your serial listener uses `ulTaskNotifyTake()`, which is event-driven and doesn't block other tasks

3. **Task Starvation**: Without a background task, the CYW43 driver timeouts waiting for CPU time

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│            FreeRTOS Kernel (configMAX_PRIORITIES = 32)      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  31 (MAX-1) ← FreeRTOS Timer Task (system reserved)       │
│                                                             │
│  27 ← Watchdog Task (periodic check)                       │
│      • Monitors protocol timeout                           │
│      • Triggers re-attestation                             │
│      • Checks system health                                │
│                                                             │
│  26 ← Serial Protocol Task (HIGH priority)                 │
│      • Listens for USB data on 0x20 ECDH request          │
│      • Processes received protocol messages                │
│      • Sends authentication responses                      │
│      • Blocked on ulTaskNotifyTake() (event-driven)       │
│                                                             │
│  25 ← WiFi Background Task (MEDIUM-HIGH priority)         │
│      • Runs every 50-100ms                                 │
│      • Calls CYW43 driver polling functions                │
│      • Handles network events                              │
│      • Processes lwIP timers                               │
│                                                             │
│  10 ← HTTP Server Task (LOW priority)                     │
│      • Listens on TCP port 80                              │
│      • Handles GET/POST requests                           │
│      • Returns configuration/status responses              │
│      • Can block on socket I/O (low priority ok)          │
│                                                             │
│  0 ← Idle Task (system reserved)                           │
│      • Runs when no other tasks ready                      │
│      • Calls FreeRTOS hooks                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Key Design Principles

### 1. Priority Ordering is Critical

```
Serial (26) > WiFi-BG (25) > HTTP (10)
```

**Why this matters**:
- Serial must never be blocked by WiFi operations
- WiFi background must run frequently (not starved by HTTP)
- HTTP can be starved occasionally (client waits, no protocol timeout)

**Result**: Serial protocol remains responsive even if WiFi is busy

### 2. Event-Driven Serial (Not Polling)

```c
// Serial task blocks on USB interrupt
void serial_task(void *params) {
    while (true) {
        // Block until USB data arrives
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(100));  // Wake on ISR
        
        // Process received data
        process_serial_data();
    }
}

// USB ISR fires when data arrives
void tud_cdc_rx_cb(uint8_t itf) {
    vTaskNotifyGiveFromISR(serial_task_handle, NULL);  // Wake task
}
```

**Benefits**:
- ✅ Serial task sleeps when no data (not busy-waiting)
- ✅ Other tasks get CPU time immediately
- ✅ Minimal power consumption
- ✅ Deterministic latency on incoming data

### 3. WiFi Background Task with Fixed Interval

```c
// WiFi background task runs periodically
void wifi_background_task(void *params) {
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(50));  // 50ms interval
        
        // Let CYW43 driver process events
        cyw43_arch_poll();
        
        // lwIP timers are called internally
    }
}
```

**Why 50ms**:
- CYW43 driver can timeout if not called for ~100ms
- 50ms gives 2x margin for safety
- Low enough for responsive network (20 calls/sec)
- Not so frequent to waste CPU cycles

### 4. HTTP Server Task with Blocking I/O

```c
// HTTP server uses lwIP blocking sockets
void http_server_task(void *params) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    bind(server_socket, ...);
    listen(server_socket, 1);
    
    while (true) {
        // Block on accept (ok because low priority)
        int client_socket = accept(server_socket, NULL, NULL);
        
        // Handle HTTP request
        http_handle_request(client_socket);
        
        close(client_socket);
    }
}
```

**Why this works**:
- HTTP can block without affecting serial (different priorities)
- If HTTP is blocked, higher-priority tasks still run
- When client connects, HTTP wakes up and serves immediately

## Task Interaction Diagram

```
┌──────────────────────────────────────────────────────────────┐
│ USB Cable - Host PC                                          │
└─────────────────┬──────────────────────────────────────────┘
                  │ CDC Serial Data
                  ↓
        ┌─────────────────────┐
        │   TinyUSB Device    │
        │    (Pico W/RP2350)  │
        └──────────┬──────────┘
                   │ (ISR) tud_cdc_rx_cb()
                   ↓
      ┌────────────────────────────────────┐
      │ FreeRTOS Scheduler                │
      │ Wakes: Serial Task (priority 26)  │
      └────────────────────────────────────┘
                   │
        ┌──────────┼──────────┐
        ↓          ↓          ↓
   ┌────────┐ ┌────────┐ ┌────────┐
   │Serial  │ │WiFi-BG │ │HTTP    │
   │26      │ │25      │ │10      │
   │Running │ │Waiting │ │Waiting │
   └────────┘ └────────┘ └────────┘
        │          │          │
        └──────────┼──────────┘
                   │ (every 50ms)
        ┌──────────┴──────────┐
        ↓                     │
   Processes        ┌─────────┴──────────┐
   Protocol         ↓                    ↓
   Message      Calls            lwIP Event
                cyw43_arch_poll()     Handler
                    │
                    ↓ (WiFi event ready?)
                Process CYW43 Event
                    │
        ┌───────────┴───────────┐
        ↓                       ↓
   DHCP/DNS              HTTP Request
   Client                  Arrives
   Connection
   (to 192.168.4.1)
```

## Task Lifecycle

### Initialization Phase (Before vTaskStartScheduler)

```c
// main()
{
    // 1. Crypto initialization
    crypt_init();  // ATECC608A setup
    
    // 2. Serial initialization
    serial_init();  // USB CDC setup, but no task yet
    
    // 3. WiFi HARDWARE initialization (must be before scheduler!)
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    wifi_ap_init();  // CYW43 chip init, gpio setup
    #endif
    
    // 4. Create FreeRTOS tasks
    xTaskCreate(serial_task, "Serial", ..., 26, ...);
    xTaskCreate(watchdog_task, "WD", ..., 27, ...);
    xTaskCreate(wifi_background_task, "WiFi-BG", ..., 25, ...);
    xTaskCreate(http_server_task, "HTTP", ..., 10, ...);
    
    // 5. Start scheduler
    vTaskStartScheduler();  // Never returns
}
```

**Critical**: `wifi_ap_init()` MUST be called before `vTaskStartScheduler()`

### Runtime Phase (After vTaskStartScheduler)

```
Time T=0ms:
  Serial Task:  Blocks on ulTaskNotifyTake()
  WiFi Task:    Blocks on vTaskDelay(50ms)
  HTTP Task:    Blocks on socket accept()

Time T=50ms:
  Scheduler wakes WiFi Task (timer expired)
  WiFi Task runs: cyw43_arch_poll() → process WiFi events
  Serial Task:    Still blocked (no USB data)
  HTTP Task:      Still blocked (no connection)

Time T=100ms:
  Scheduler wakes WiFi Task again (timer expired)
  Host sends USB data → Serial Task wakes (higher priority than WiFi)
  Serial Task runs: process_serial_data() → sends response
  WiFi Task:       Paused (Serial has higher priority)

Time T=150ms:
  Scheduler wakes WiFi Task (timer expired)
  WiFi Task runs: cyw43_arch_poll()
  HTTP client connects via WiFi
  HTTP Task wakes: Accepts connection, serves response
```

## Timing Constraints

### Serial Response Time (Critical)

```
Host sends ECDH Share
       ↓
USB ISR fires (immediate)
       ↓
Serial Task wakes (priority 26)
       ↓
Token processes ECDH (compute shared secret ~100ms)
       ↓
Token sends T2H_ECDH_SHARE
       ↓
Host receives (typically <1ms for local USB)
```

**Requirement**: < 200ms total (including CPU time)  
**Actual with WiFi**: ~100-150ms (WiFi doesn't interfere)

### WiFi Background Task Frequency

```
CYW43 Timeout Check: Every packet TX/RX requires processing
  ├─ If not called for ~100ms → packet drops
  └─ If called every 50ms → safe margin

WiFi Background Task Delay: 50ms
  ├─ Runs every 50ms (20 calls/second)
  ├─ Even if Serial takes 10ms → 40ms gap to next WiFi call
  └─ CYW43 sees 50ms interval ✓ (within timeout)
```

### HTTP Server Response Time (Not Critical)

```
Browser sends GET request
       ↓
Network arrives in CYW43 buffer
       ↓
WiFi Background Task processes (next 50ms tick)
       ↓
lwIP processes packet → triggers HTTP task
       ↓
HTTP Task wakes (can wait 50-100ms if Serial active)
       ↓
HTTP sends response
       ↓
Browser sees response (500ms+ acceptable for web config)
```

## Context Switching Scenarios

### Scenario 1: Serial Message During WiFi Processing

```
Timeline:
T=25ms: WiFi Task running cyw43_arch_poll()
        │
        └─ Host sends USB data
           │
           └─ USB ISR fires
              │
              └─ vTaskNotifyGiveFromISR(Serial)
                 │
                 └─ Scheduler preempts WiFi Task (26 > 25)
                    │
                    └─ Serial Task runs immediately
                       Processes protocol message
                       Sends response
                       Blocks on next ulTaskNotifyTake()
                       │
                       └─ Scheduler resumes WiFi Task
                          Where it left off in cyw43_arch_poll()

Result: ~1-5ms latency for Serial, WiFi continues
```

### Scenario 2: HTTP Request During Serial Processing

```
Timeline:
T=50ms: WiFi Task calls cyw43_arch_poll()
        Processes packet: GET /api/status
        Wakes HTTP Task
        │
        └─ Scheduler: Check priorities
           Serial (26) > HTTP (10)
           │
           └─ If Serial Task is waiting: stays waiting
              WiFi (25) > HTTP (10)
              │
              └─ WiFi continues running
                 WiFi Task blocks/yields
                 │
                 └─ Scheduler runs HTTP Task
                    Reads HTTP socket
                    Sends response
                    Blocks on next accept()
                    │
                    └─ Scheduler runs lower priority tasks

Result: HTTP sees ~50-100ms latency (acceptable for web)
```

### Scenario 3: Everything Running Together

```
T=0ms:    Serial wakes (USB data arrived)
T=2ms:    Serial processing ECDH (lots of CPU)
T=5ms:    WiFi timer expires (but Serial has 26 > 25)
T=10ms:   Serial sends response, blocks
          Scheduler runs WiFi (no higher priority)
T=10ms:   WiFi runs cyw43_arch_poll()
T=12ms:   HTTP request processed by WiFi
          HTTP wakes
T=15ms:   HTTP runs (no higher priority)
T=18ms:   HTTP sends response, blocks
T=20ms:   Serial wakes (next heartbeat)
T=22ms:   Serial runs, WiFi waits
...
```

Result: All tasks run in correct priority order, no conflicts

## Memory Layout

### Task Stack Sizes

| Task | Stack Size | Reason |
|------|-----------|--------|
| Serial | 2048 bytes | Protocol processing, modest stack |
| WiFi-BG | 2048 bytes | CYW43 calls (moderate stack usage) |
| HTTP | 4096 bytes | Socket I/O, HTTP parsing (larger) |
| Watchdog | 1024 bytes | Simple time checks (minimal) |
| **Total** | **~11KB** | Allocated by FreeRTOS heap (out of 264KB available) |

### CYW43 & lwIP Memory

- **CYW43 buffers**: ~32KB (allocated once at init)
- **lwIP pools**: ~16KB (TCP, UDP, IP buffers)
- **Total overhead**: ~50KB (still safe on Pico W with 264KB RAM)

## CPU Utilization Profile

```
Serial Task:
  • Blocks 95% of time (waiting for USB)
  • CPU 5% (when processing protocol messages)

WiFi Background Task:
  • Blocks 90% of time (on vTaskDelay)
  • CPU 10% (CYW43 polling, lwIP processing)

HTTP Server Task:
  • Blocks 98% of time (waiting for connections)
  • CPU 2% (serving requests when they arrive)

Watchdog Task:
  • Runs 1% of time (quick timeout check)
  • Blocks 99% of time

Total CPU:
  • Average: ~10-15% utilized
  • Peak: ~30-40% (Serial ECDH + HTTP response simultaneously)
  • Reserved for overhead: ~5%
```

## Failure Modes & Recovery

### Failure: WiFi Background Task Deleted/Crashed

```
Symptom: WiFi stops responding, but serial still works
Cause: Task priority 25 crashed or was deleted
Recovery: (none) Must restart device
Prevention: Implement task watchdog to restart if needed
```

### Failure: Serial Task Starved

```
Symptom: ECDH timeout (serial responses delayed)
Cause: Higher priority task (27, 26) running too long
Recovery: Reduce CPU time in those tasks
Prevention: Don't create tasks with priority > 26
```

### Failure: HTTP Socket Accepts from Wrong Interface

```
Symptom: HTTP doesn't respond to WiFi connections
Cause: HTTP listening on USB instead of WiFi
Recovery: HTTP must listen on all interfaces (0.0.0.0:80)
Prevention: Use wildcard binding in socket setup
```

## Next Steps

See `6_WIFI_QUICK_IMPLEMENTATION.md` for copy-paste code to implement this architecture.
