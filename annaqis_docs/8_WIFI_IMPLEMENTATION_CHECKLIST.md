# WiFi Implementation Checklist

Step-by-step guide to implement WiFi AP integration. **Expected time: 20-30 minutes.**

## Pre-Implementation

- [ ] Pico W / RP2350 W device with ATECC608A crypto chip
- [ ] USB connection to development PC
- [ ] Build system ready (`cmake`, `make`, `openocd` or `picoprobe`)
- [ ] Latest Pico SDK downloaded
- [ ] FreeRTOS configured in project

## Phase 1: CMakeLists.txt Updates (5 min)

### Step 1.1: Open CMakeLists.txt

- [ ] Open `/path/to/project/CMakeLists.txt`
- [ ] Verify it contains `pico_sdk_init()`
- [ ] Verify it has `FreeRTOS-Kernel-Heap4` in `target_link_libraries`

### Step 1.2: Add WiFi Configuration

- [ ] Find line with `cmake_minimum_required()`
- [ ] Add after that line:
```cmake
# WiFi Configuration for CYW43 (Pico W / Pico 2 W)
set(PICO_CYW43_ARCH_THREADSAFE_BACKGROUND ON)
set(PICO_LWIP_CONTRIB_FREERTOS 1)
```

- [ ] Verify additions are BEFORE `pico_sdk_init()`

### Step 1.3: Update target_link_libraries

- [ ] Find existing `target_link_libraries(pico_project_template`
- [ ] Add to the list:
  - [ ] `pico_cyw43_arch_threadsafe_background`
  - [ ] `pico_lwip_http`
- [ ] Verify order doesn't matter (alphabetical OK)

### Step 1.4: Update add_executable

- [ ] Find `add_executable(pico_project_template`
- [ ] Add after `src/crypt.c`:
```cmake
src/wifi_ap.c
```

- [ ] Save CMakeLists.txt
- [ ] Run quick syntax check:
```bash
cd build && cmake -DPICO_BOARD=pico_w .. 2>&1 | head -20
```

- [ ] Should show no errors (may have warnings, OK)

## Phase 2: Create Header File (3 min)

### Step 2.1: Create wifi_ap.h

- [ ] Create file: `include/wifi_ap.h`
- [ ] Copy content from `6_WIFI_QUICK_IMPLEMENTATION.md` Section "Step 2: Create WiFi Header File"
- [ ] Verify 15 lines total (should be short)
- [ ] Check include guards: `#ifndef WIFI_AP_H` and `#define WIFI_AP_H`

### Step 2.2: Verify Header Syntax

```bash
cd include
cat wifi_ap.h | grep "^#" | head -5
```

- [ ] Output should show includes and guards

## Phase 3: Create Implementation File (3 min)

### Step 3.1: Create wifi_ap.c

- [ ] Create file: `src/wifi_ap.c`
- [ ] Copy content from `6_WIFI_QUICK_IMPLEMENTATION.md` Section "Step 3: Create WiFi Implementation"
- [ ] Verify file is ~150 lines

### Step 3.2: Verify Implementation Syntax

```bash
cd src
head -20 wifi_ap.c
```

- [ ] Should show proper includes (wifi_ap.h, logger.h, etc.)
- [ ] Should show `static wifi_ap_config_t wifi_config = {...}`

## Phase 4: Update main.c (8 min)

### Step 4.1: Add Header Include

- [ ] Open `src/main.c`
- [ ] Find section with `#include` statements
- [ ] Add new include:
```c
#include "wifi_ap.h"
```

- [ ] Verify it's after other includes (order: standard libs, pico libs, project libs)

### Step 4.2: Add WiFi Initialization

- [ ] Find `main()` function
- [ ] Find where `crypt_init()` is called
- [ ] Add after `crypt_init()` and `serial_init()`:
```c
    // Initialize WiFi hardware (must be BEFORE FreeRTOS starts)
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    if (!wifi_ap_init()) {
        print_error("WARNING: WiFi init failed\n");
    }
    #endif
```

- [ ] Verify this is BEFORE `xTaskCreate(serial_task, ...)`

### Step 4.3: Create WiFi Tasks

- [ ] Find where you create `serial_task` and `watchdog_task`
- [ ] Add after the watchdog task creation:
```c
    // WiFi Background Task (priority 25)
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    TaskHandle_t wifi_bg_handle;
    xTaskCreate(
        wifi_background_task,
        "WiFi-BG",
        2048,
        NULL,
        configMAX_PRIORITIES - 7,
        &wifi_bg_handle
    );
    #endif
    
    // HTTP Server Task (priority 10)
    TaskHandle_t http_handle;
    xTaskCreate(
        http_server_task,
        "HTTP-Server",
        2048,
        NULL,
        10,
        &http_handle
    );
    
    // WiFi Init Task
    TaskHandle_t wifi_init_handle;
    xTaskCreate(
        wifi_init_task,
        "WiFi-Init",
        2048,
        NULL,
        5,
        &wifi_init_handle
    );
```

- [ ] Verify this is BEFORE `vTaskStartScheduler()`

### Step 4.4: Add WiFi Init Task Function

- [ ] Add this function BEFORE `main()`:
```c
void wifi_init_task(void *params) {
    (void)params;
    
    vTaskDelay(pdMS_TO_TICKS(500));
    
    #if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    wifi_ap_config_t config = {
        .ssid = "MASTR-Token",
        .password = "MastrToken123",
    };
    
    if (wifi_ap_start(&config)) {
        print_info("WiFi AP started successfully\n");
    } else {
        print_error("Failed to start WiFi AP\n");
    }
    #endif
    
    vTaskDelete(NULL);
}
```

- [ ] Verify function is complete (has all braces)

## Phase 5: Build Verification (5 min)

### Step 5.1: Clean Build

```bash
cd build
rm -rf *
cmake -DPICO_BOARD=pico_w ..
make -j4
```

- [ ] Build completes without errors
- [ ] Output shows:
  - [ ] `src/wifi_ap.c` being compiled
  - [ ] `Linking CXX executable` (or similar)
  - [ ] `[100%]` progress
  - [ ] `Built target pico_project_template`

### Step 5.2: Check for Warnings

```bash
make 2>&1 | grep -i "warning" | head -10
```

- [ ] Warnings about unused variables are OK
- [ ] Errors should be ZERO
- [ ] If errors: Review Step 4 (main.c edits)

### Step 5.3: Verify Binary Generated

```bash
ls -lh build/pico_project_template.uf2
```

- [ ] File should exist and be > 100KB
- [ ] File should be readable

## Phase 6: Flashing (5 min)

### Step 6.1: Prepare Device

- [ ] Connect Pico W via USB (data cable)
- [ ] Hold BOOTSEL button and press RESET
- [ ] Device should appear as USB storage
- [ ] Verify: `lsblk` or `ls /Volumes/RPI-RP2` (Mac)

### Step 6.2: Flash Firmware

**Option A: Drag & Drop (Easiest)**
- [ ] Copy `build/pico_project_template.uf2` to device storage
- [ ] Wait for device to unmount (usually <5 seconds)
- [ ] Device should restart automatically

**Option B: openocd (If using picoprobe)**
```bash
openocd -f interface/picoprobe.cfg -f target/rp2350.cfg \
  -c "program build/pico_project_template.uf2 verify reset"
```
- [ ] Should show "verified" message
- [ ] Device should restart

### Step 6.3: Verify Flashing

- [ ] Device should restart (LED blink pattern might change)
- [ ] No error messages during programming

## Phase 7: Serial Monitoring (3 min)

### Step 7.1: Start Serial Monitor

```bash
minicom -D /dev/ttyACM0 -b 115200
# or on Mac: minicom -D /dev/cu.usbmodem14101 -b 115200
# or use PuTTY / screen / picocom
```

- [ ] Connect successfully (no "Permission denied" errors)
- [ ] Screen shows debug output

### Step 7.2: Look for WiFi Startup Messages

- [ ] Should see (in order):
  1. `WiFi hardware initialized (AP mode ready)`
  2. `WiFi background task started`
  3. `HTTP server task started`
  4. `WiFi AP started: MASTR-Token (192.168.4.1)`

- [ ] If messages missing: Note which ones for debugging

### Step 7.3: Keep Monitor Running

- [ ] Leave minicom open for testing phase
- [ ] Can minimize window but keep running

## Phase 8: WiFi Connectivity Test (5 min)

### Step 8.1: Scan WiFi Networks

**On test device (phone/laptop)**:
- [ ] Open WiFi network list
- [ ] Look for network named `MASTR-Token`
- [ ] If found: ✓ SSID Broadcasting OK

**If NOT found**:
- [ ] Check serial output for AP startup messages
- [ ] If missing: Restart device (disconnect/reconnect USB)
- [ ] If still missing: See `7_WIFI_DETAILED_GUIDE.md` Troubleshooting

### Step 8.2: Connect to Network

**On test device**:
- [ ] Select `MASTR-Token` network
- [ ] Enter password: `MastrToken123`
- [ ] Wait for connection (10-30 seconds)

**Expected progression**:
- [ ] "Connecting..." (5-10 sec)
- [ ] "Obtaining IP..." (5-10 sec)
- [ ] "Connected" (shows IP like 192.168.4.x)

**If timeout/fails**:
- [ ] Check serial monitor for errors
- [ ] Try again (sometimes takes 2 attempts)
- [ ] See `7_WIFI_DETAILED_GUIDE.md` "Issue: Clients Can't Connect"

### Step 8.3: Verify IP Assignment

- [ ] Check network settings on test device
- [ ] Note assigned IP (should be 192.168.4.2+)
- [ ] Ping gateway:
```bash
ping 192.168.4.1
```
- [ ] Should get responses (3-4 ping replies)

**If ping fails**:
- [ ] IP not assigned (DHCP issue)
- [ ] See `7_WIFI_DETAILED_GUIDE.md` "Issue: Clients Can't Connect but No DHCP IP"

## Phase 9: HTTP Server Test (3 min)

### Step 9.1: Test HTTP Connection

**From connected device**:
```bash
curl http://192.168.4.1/
# or open browser: http://192.168.4.1
```

- [ ] Should connect (doesn't error with timeout)
- [ ] May get "404 Not Found" (OK, no content yet)
- [ ] May get default page (depends on lwIP version)

**If timeout/connection refused**:
- [ ] Check serial output (HTTP errors?)
- [ ] Verify HTTP task is running
- [ ] See `7_WIFI_DETAILED_GUIDE.md` "Issue: HTTP Requests Timeout"

### Step 9.2: Check Serial Output

**In minicom**, look for HTTP messages:
- [ ] May see "HTTP GET /" log message
- [ ] Shows HTTP task is processing requests

## Phase 10: Serial Protocol Test (3 min)

### Step 10.1: Verify Serial Still Works

**From serial monitor**:
- [ ] Should still see protocol messages
- [ ] Serial protocol should not be blocked by WiFi

**If serial hangs or drops messages**:
- [ ] Check task priorities (must be: Serial 26 > WiFi 25)
- [ ] See `7_WIFI_DETAILED_GUIDE.md` "Issue: Serial Protocol Drops Messages"

### Step 10.2: Test Attestation

**From host**:
- [ ] Run host attestation code
- [ ] Should complete successfully
- [ ] Verify WiFi doesn't interfere with protocol

## Phase 11: Verification Checklist

### System Status

- [ ] Device boots successfully
- [ ] No boot errors in serial output
- [ ] All 4 WiFi startup messages appear

### WiFi AP

- [ ] SSID "MASTR-Token" visible
- [ ] Can connect with password
- [ ] DHCP assigns IP (192.168.4.x)
- [ ] Can ping gateway (192.168.4.1)

### HTTP Server

- [ ] `curl http://192.168.4.1/` responds
- [ ] No timeout errors
- [ ] Response received within 2 seconds

### Serial Protocol

- [ ] Serial still operational
- [ ] Protocol messages flowing
- [ ] No dropped messages
- [ ] Attestation completes normally

### Task Execution

- [ ] Serial task running (handling protocol)
- [ ] WiFi task running (every 50ms)
- [ ] HTTP task responsive to connections
- [ ] No CPU/memory issues in logs

## Common Issues & Quick Fixes

| Issue | Quick Fix |
|-------|-----------|
| **CMake build fails** | Ensure `DPICO_BOARD=pico_w` is set |
| **Serial won't compile** | Check `#include "wifi_ap.h"` added |
| **WiFi not starting** | Verify `wifi_ap_init()` called before scheduler |
| **SSID not visible** | Add 2 second delay, devices cache networks |
| **Can't get IP** | Increase sleep after scheduler (500ms→1000ms) |
| **HTTP timeout** | Verify `httpd_init()` called in `wifi_ap_start()` |
| **Serial drops** | Check Serial priority is 26, WiFi is 25 |

## Rollback Procedure

If integration causes issues:

1. Revert CMakeLists.txt changes
2. Delete `src/wifi_ap.c` and `include/wifi_ap.h`
3. Revert `src/main.c` (remove WiFi includes/tasks)
4. Rebuild and reflash

Expected time: 5 minutes

## Success Criteria

✅ **All of the following must be true**:

1. Device boots without errors
2. WiFi SSID broadcasts successfully
3. Client can connect and get DHCP IP
4. HTTP server responds on port 80
5. Serial protocol continues working
6. No message drops or timeouts
7. Device remains stable for >5 minutes

**If any criterion fails**: See `7_WIFI_DETAILED_GUIDE.md` for detailed troubleshooting.

## Next Steps After Success

1. **Implement HTTP API endpoints** - See `7_WIFI_DETAILED_GUIDE.md`
2. **Add web configuration UI** - Serve HTML from flash
3. **Add OTA updates** - Update firmware over WiFi
4. **Add monitoring** - Dashboard showing token status
5. **Add logging** - Store events locally or upload to cloud

## Support Resources

- `4_WIFI_PROBLEM_ANALYSIS.md` - Why WiFi didn't work initially
- `5_WIFI_SOLUTION_ARCHITECTURE.md` - Task scheduling explanation
- `6_WIFI_QUICK_IMPLEMENTATION.md` - Copy-paste code
- `7_WIFI_DETAILED_GUIDE.md` - Advanced topics & troubleshooting
- `1_ATTESTATION_STATE_MACHINE.md` - Serial protocol reference

---

**Estimated Total Time**: 30-40 minutes including testing

**Help?** Start at `7_WIFI_DETAILED_GUIDE.md` Troubleshooting section.
