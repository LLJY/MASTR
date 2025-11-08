# Your AP Module Integration Checklist

## Quick Summary

Your `net/` module is **excellent quality** ✅

**Integration approach**: Create a thin FreeRTOS wrapper layer to adapt your standalone AP module into the MASTR task system.

---

## Files to Create/Modify

### 📝 New Files to Create

- [ ] `/src/net_freertos.h` - Wrapper API header
- [ ] `/src/net_freertos.c` - FreeRTOS integration code

### ✏️ Files to Modify

- [ ] `/CMakeLists.txt` - Add net sources + WiFi config
- [ ] `/src/main.c` - Add WiFi tasks + initialization
- [ ] `/net/ap/ap_manager.c` - Change `printf()` → `print_dbg()`
- [ ] `/net/http/http_server.c` - Change `printf()` → `print_dbg()`
- [ ] `/net/api/api.c` - Add `#include "serial.h"` for print_dbg
- [ ] `/net/api/api.c` - Change `printf()` → `print_dbg()`

---

## Step-by-Step Integration

### Step 1️⃣: Create FreeRTOS Wrapper Layer (5 min)

**File**: Create `/src/net_freertos.h`

```c
#ifndef NET_FREERTOS_H
#define NET_FREERTOS_H

int net_ap_init_hardware(void);
int net_ap_start(const char *ssid, const char *password);
void net_ap_stop(void);
void net_background_task(void *params);

#endif
```

**File**: Create `/src/net_freertos.c`

```c
#include "net_freertos.h"
#include "ap/ap_manager.h"
#include "pico/cyw43_arch.h"
#include "serial.h"
#include "FreeRTOS.h"
#include "task.h"

int net_ap_init_hardware(void) {
    if (cyw43_arch_init()) {
        print_dbg("ERROR: CYW43 init failed\n");
        return -1;
    }
    print_dbg("WiFi hardware initialized\n");
    return 0;
}

int net_ap_start(const char *ssid, const char *password) {
    int result = start_access_point(ssid, password);
    if (result == 0) {
        print_dbg("WiFi AP started: %s (192.168.4.1)\n", ssid);
    } else {
        print_dbg("ERROR: Failed to start WiFi AP\n");
    }
    return result;
}

void net_ap_stop(void) {
    stop_access_point();
    print_dbg("WiFi AP stopped\n");
}

void net_background_task(void *params) {
    (void)params;
    print_dbg("WiFi background task started\n");
    
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(50));
        cyw43_arch_poll();
    }
}
```

✅ Done: Wrapper layer abstracts your AP module for FreeRTOS

---

### Step 2️⃣: Update CMakeLists.txt (5 min)

**Location**: `/CMakeLists.txt`

**Around line 19 (after `cmake_minimum_required`):**
```cmake
# WiFi Configuration
set(PICO_CYW43_ARCH_THREADSAFE_BACKGROUND ON)
set(PICO_LWIP_CONTRIB_FREERTOS 1)
```

**Around line 154 (in `add_executable`):**

Add these lines:
```cmake
    net/ap/ap_manager.c
    net/http/http_server.c
    net/dhcp/dhcpserver.c
    net/api/api.c
    src/net_freertos.c
```

**Around line 178 (in `target_include_directories`):**

Add:
```cmake
    ${CMAKE_CURRENT_LIST_DIR}/net
```

**Around line 166 (in `target_link_libraries`):**

Add:
```cmake
    pico_cyw43_arch_threadsafe_background
    pico_lwip_http
```

✅ Done: Build system knows about net/ modules

---

### Step 3️⃣: Update src/main.c (10 min)

**Location**: `/src/main.c`

**Around line 13 (after other includes):**
```c
#include "net_freertos.h"
```

**Around line 102 (after `crypt_init()`, BEFORE task creation):**
```c
    // Initialize WiFi hardware (must be BEFORE FreeRTOS starts)
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    if (net_ap_init_hardware() != 0) {
        print_dbg("WARNING: WiFi hardware init failed\n");
    }
    #endif
```

**Around line 130 (after watchdog task creation):**
```c
    // WiFi Background Task (priority 25)
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    TaskHandle_t net_bg_handle;
    xTaskCreate(
        net_background_task,
        "Net-BG",
        DEFAULT_STACK_SIZE,
        NULL,
        configMAX_PRIORITIES - 7,
        &net_bg_handle
    );
    
    // WiFi Init Task
    TaskHandle_t net_init_handle;
    xTaskCreate(
        net_init_task,
        "Net-Init",
        DEFAULT_STACK_SIZE,
        NULL,
        5,
        &net_init_handle
    );
    #endif
```

**Before `main()` function (after `watchdog_task()`):**
```c
void net_init_task(void *params) {
    (void)params;
    vTaskDelay(pdMS_TO_TICKS(500));
    
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    if (net_ap_start("MASTR-Token", "MastrToken123") == 0) {
        print_dbg("WiFi AP ready\n");
    }
    #endif
    
    vTaskDelete(NULL);
}
```

✅ Done: WiFi integrated into FreeRTOS task system

---

### Step 4️⃣: Fix Logging in net/ Files (5 min)

**File**: `/net/ap/ap_manager.c`

Find any `printf()` calls and replace with:
```c
#include "serial.h"  // Add to includes

// Then change all:
// printf(...) → print_dbg(...)
```

**File**: `/net/http/http_server.c`

Same as above.

**File**: `/net/api/api.c`

Add to includes:
```c
#include "serial.h"
```

Change `printf()` to `print_dbg()`.

✅ Done: Logging consistent with MASTR patterns

---

### Step 5️⃣: Build & Test (10 min)

**Clean build:**
```bash
cd build
rm -rf *
cmake -DPICO_BOARD=pico_w ..
make -j4
```

**Expected output:**
```
[100%] Built target pico_project_template
```

**Flash:**
```bash
# Copy .uf2 to Pico W or use openocd
```

**Serial monitor:**
```bash
minicom -D /dev/ttyACM0 -b 115200
```

**Expected messages:**
```
WiFi hardware initialized
WiFi background task started
WiFi AP ready
```

**Test WiFi:**
- Scan: See "MASTR-Token" network
- Connect: Password "MastrToken123"
- DHCP: Get 192.168.4.x IP
- API: `curl http://192.168.4.1/api/ping`

**Test Serial:**
- Verify protocol still works
- No message drops

✅ Done: Integration complete!

---

## Estimated Time

| Phase | Time |
|-------|------|
| Create wrapper files | 5 min |
| Update CMakeLists.txt | 5 min |
| Update main.c | 10 min |
| Fix logging | 5 min |
| Build & test | 15 min |
| **Total** | **40 min** |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Build fails: "ap_manager.h not found" | Check `target_include_directories` has `net/` |
| Build fails: "undefined reference to start_access_point" | Check `net/ap/ap_manager.c` in `add_executable` |
| WiFi not starting | Check `net_ap_init_hardware()` called before scheduler |
| HTTP requests timeout | Check `net_background_task` is running (see serial output) |
| Serial protocol fails | Check WiFi task priority is 25 (below serial's 26) |
| No debug messages | Check logging changed from `printf` to `print_dbg` |

---

## Files Summary

**Your module files** (don't modify, just build):
- `/net/ap/ap_manager.c` ← Main integration point
- `/net/http/http_server.c`
- `/net/dhcp/dhcpserver.c`
- `/net/api/api.c`

**Files you create**:
- `/src/net_freertos.c` ← Wrapper layer
- `/src/net_freertos.h` ← Wrapper API

**Files you modify**:
- `/CMakeLists.txt`
- `/src/main.c`
- `/net/*` (logging only)

---

## Next Actions

1. ✅ Read this checklist
2. ⬜ Create wrapper files (Step 1)
3. ⬜ Update CMakeLists.txt (Step 2)
4. ⬜ Update main.c (Step 3)
5. ⬜ Fix logging (Step 4)
6. ⬜ Build (Step 5)
7. ⬜ Test WiFi + Serial
8. ⬜ Done!

---

**Ready to start?** Begin with Step 1 - it's the quickest and confirms your approach works!
