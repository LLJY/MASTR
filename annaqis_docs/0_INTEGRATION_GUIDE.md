# WiFi Integration - Your Code Structure Analysis

## Your MASTR Project Architecture

Your codebase is well-organized with clean separation of concerns:

```
/MASTR/
├── CMakeLists.txt              (Build configuration)
├── include/
│   ├── constants.h             (Frame format: SOF, EOF, ESC)
│   ├── protocol.h              (State machine: 0x20, 0x21, ..., 0xFF)
│   ├── crypt.h                 (ATECC608A crypto operations)
│   ├── serial.h                (USB CDC, uses print_dbg())
│   ├── FreeRTOSConfig.h         (Scheduler config)
│   └── mbedtls_config.h
├── src/
│   ├── main.c                  (Entry point, task creation)
│   ├── serial.c                (USB interrupt handling)
│   ├── protocol.c              (State machine logic)
│   ├── crypt.c                 (Crypto subsystem)
│   ├── hal/hal_pico_i2c.c       (I2C HAL for ATECC)
│   └── [WIFI FILES GO HERE]
├── test/                        (Unit tests)
└── docs/                        (Documentation)
```

---

## Key Patterns in Your Code

### 1. Logging System
Your code uses `print_dbg()` for all debug output:

```c
print_dbg("WiFi hardware initialized\n");
print_dbg("ERROR: CYW43 init failed\n");
print_dbg("Watchdog: Session timeout detected\n");
```

**Pattern**: `print_dbg(format, args...)` - Works like `printf()`  
**WiFi Integration**: Use `print_dbg()` consistently (not `printf`)

### 2. Task Creation Pattern
From your `main.c`:

```c
TaskHandle_t serial_task_handle;
xTaskCreate(
    serial_task,                    // Function pointer
    "Serial",                       // Name (human-readable)
    DEFAULT_STACK_SIZE,             // From constants.h (2048 for RP2350)
    NULL,                           // Parameters
    configMAX_PRIORITIES - 6,       // Priority (26)
    &serial_task_handle             // Output handle
);
```

**Pattern**: All tasks follow this structure  
**WiFi Integration**: WiFi tasks use same pattern with priorities 25 (BG) and 10 (HTTP)

### 3. Task Priority Hierarchy
From comments in your `main.c`:

```
31 (MAX-1)   : Timer task (FreeRTOS system)
27           : Watchdog task (session monitoring)
26           : Serial task (protocol processing)
25           : ← WiFi Background task (FITS HERE)
10-15        : ← HTTP Server task (FITS HERE)
0            : Idle task
```

**Your Serial**: Priority 26, cannot be blocked by lower priorities  
**Your Watchdog**: Priority 27, high priority for safety  
**WiFi-BG**: Priority 25 (just below serial)  
**HTTP**: Priority 10 (low, can wait)

### 4. Initialization Sequence in main()

```c
int main() {
    // 1. Early initialization
    stdio_init_all();
    
    // 2. Hardware initialization
    atcab_init(&cfg);           // ATECC608A
    crypt_init();               // Crypto subsystem
    
    // → WIFI_AP_INIT GOES HERE (before scheduler!)
    
    // 3. Task creation (all BEFORE scheduler)
    xTaskCreate(serial_task, ...);
    xTaskCreate(watchdog_task, ...);
    
    // → WIFI TASKS CREATED HERE
    
    // 4. Per-subsystem initialization with handles
    serial_init(serial_task_handle);
    protocol_state initialization...
    
    // 5. Start scheduler (never returns)
    vTaskStartScheduler();
}
```

**Critical**: `wifi_ap_init()` MUST be before `vTaskStartScheduler()`

---

## Integration Changes Required

### Change 1: CMakeLists.txt

**File**: `/Users/annaqikun/Documents/Embed/final/MASTR/CMakeLists.txt`

**Line ~19** - Add WiFi configuration:
```cmake
# WiFi Configuration for CYW43 (Pico W / Pico 2 W)
set(PICO_CYW43_ARCH_THREADSAFE_BACKGROUND ON)
set(PICO_LWIP_CONTRIB_FREERTOS 1)
```

**Line ~167-172** - Update `target_link_libraries()`:

**BEFORE**:
```cmake
target_link_libraries(pico_project_template
    pico_stdlib
    hardware_i2c
    cryptoauth
    pico_mbedtls
    FreeRTOS-Kernel-Heap4
    freertos_config)
```

**AFTER**:
```cmake
target_link_libraries(pico_project_template
    pico_stdlib
    pico_cyw43_arch_threadsafe_background
    pico_lwip_http
    hardware_i2c
    cryptoauth
    pico_mbedtls
    FreeRTOS-Kernel-Heap4
    freertos_config)
```

**Line ~154-161** - Update `add_executable()`:

**BEFORE**:
```cmake
add_executable(pico_project_template
    src/main.c
    src/serial.c
    src/protocol.c
    src/crypt.c
    src/hal/hal_pico_i2c.c
)
```

**AFTER**:
```cmake
add_executable(pico_project_template
    src/main.c
    src/serial.c
    src/protocol.c
    src/crypt.c
    src/wifi_ap.c
    src/hal/hal_pico_i2c.c
)
```

---

### Change 2: Create Header File

**File**: Create `/Users/annaqikun/Documents/Embed/final/MASTR/include/wifi_ap.h`

This follows your modular pattern with a clean public API.

---

### Change 3: Create Implementation File

**File**: Create `/Users/annaqikun/Documents/Embed/final/MASTR/src/wifi_ap.c`

Implements:
- `wifi_ap_init()` - Hardware initialization (called before scheduler)
- `wifi_ap_start()` - Start AP with configuration
- `wifi_background_task()` - FreeRTOS task at priority 25
- `http_server_task()` - FreeRTOS task at priority 10

---

### Change 4: Update main.c

**File**: `/Users/annaqikun/Documents/Embed/final/MASTR/src/main.c`

**Add Include** (after line 13, with other includes):
```c
#include "wifi_ap.h"
```

**Add WiFi Hardware Init** (after `crypt_init()` around line 102, BEFORE task creation):
```c
    // Initialize WiFi hardware (must be BEFORE FreeRTOS starts)
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    if (!wifi_ap_init()) {
        print_dbg("WARNING: WiFi init failed\n");
    }
    #endif
```

**Add WiFi Tasks** (after watchdog task creation, before `serial_init()`):
```c
    // WiFi Background Task (priority 25, runs every 50ms)
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    TaskHandle_t wifi_bg_handle;
    xTaskCreate(
        wifi_background_task,
        "WiFi-BG",
        DEFAULT_STACK_SIZE,
        NULL,
        configMAX_PRIORITIES - 7,  // Priority 25
        &wifi_bg_handle
    );
    
    // HTTP Server Task (priority 10)
    TaskHandle_t http_handle;
    xTaskCreate(
        http_server_task,
        "HTTP-Server",
        DEFAULT_STACK_SIZE,
        NULL,
        10,
        &http_handle
    );
    
    // WiFi Init Task (starts AP after scheduler)
    TaskHandle_t wifi_init_handle;
    xTaskCreate(
        wifi_init_task,
        "WiFi-Init",
        DEFAULT_STACK_SIZE,
        NULL,
        5,
        &wifi_init_handle
    );
    #endif
```

**Add WiFi Init Task Function** (before `main()` function, after `watchdog_task()`):
```c
void wifi_init_task(void *params) {
    (void)params;
    
    // Wait for system stabilization
    vTaskDelay(pdMS_TO_TICKS(500));
    
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "MastrToken123",
    };
    
    if (wifi_ap_start(&config)) {
        print_dbg("WiFi AP started successfully\n");
    } else {
        print_dbg("ERROR: Failed to start WiFi AP\n");
    }
    #endif
    
    // Task complete, delete self
    vTaskDelete(NULL);
}
```

---

## Code Alignment with Your Patterns

| Aspect | Your Code | WiFi Code | Status |
|--------|-----------|-----------|--------|
| **Logging** | `print_dbg()` | `print_dbg()` | ✅ Match |
| **Task Priority** | `configMAX_PRIORITIES - N` | `configMAX_PRIORITIES - 7` | ✅ Consistent |
| **Stack Size** | `DEFAULT_STACK_SIZE` | `DEFAULT_STACK_SIZE` | ✅ Consistent |
| **Init Order** | Before scheduler | Before scheduler | ✅ Correct |
| **Conditional Build** | `#if defined()` | `#if defined(CYW43_...)` | ✅ Consistent |
| **Header Pattern** | Modular with API | Modular with API | ✅ Follows pattern |
| **Task Creation** | xTaskCreate() pattern | Same pattern | ✅ Consistent |

---

## Next Steps

1. **Get the Code**
   - Read: `6_WIFI_QUICK_IMPLEMENTATION.md` (has copy-paste code blocks)
   
2. **Make the Changes**
   - Update CMakeLists.txt (3 sections)
   - Create wifi_ap.h (header)
   - Create wifi_ap.c (implementation)
   - Update main.c (4 sections)
   
3. **Build & Test**
   - Follow: `8_WIFI_IMPLEMENTATION_CHECKLIST.md` (11 phases with checkboxes)

---

## Summary

✅ Your code structure analyzed  
✅ WiFi integration points identified  
✅ Changes aligned with your patterns  
✅ Priority hierarchy documented  
✅ Initialization order confirmed  

**You are ready to integrate WiFi AP!**

See `6_WIFI_QUICK_IMPLEMENTATION.md` for copy-paste code.
