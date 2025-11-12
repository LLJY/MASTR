# 🤖 MASTR Token - WiFi AP Integration

**M**utual **A**ttested **S**ecure **T**oken for **R**obotics - now with WiFi (bruh).

A tiny microcontroller trying to be both a secure token AND a WiFi router. Somehow it mostly works. 🤷

## ✨ What Works (For Real This Time)

### ✅ WiFi Access Point
- **SSID:** `MASTR-Token`
- **Password:** `MastrToken123`
- **IP:** `192.168.4.1`
- Basically: your Pico becomes a WiFi hotspot. Crazy, I know.

### ✅ HTTP API (The Good Parts)

#### `/api/ping`
```bash
curl http://192.168.4.1/api/ping
# Bruh, it responds: {"message":"pong"}
```
Simple connectivity test. Does what it says on the tin.

#### `/api/status` (Actually Works!)
```bash
curl http://192.168.4.1/api/status
# Returns: {"provisioned":true/false, "state":"0x40", "uptime_s":123}
```
Tells you if the token is provisioned yet. That's literally it. Works great.

#### `/api/info` 
**NOPE.** Crashes immediately. Disabled. Don't ask. 💀

### 🌐 Web Dashboard
- Open `http://192.168.4.1/` in your browser
- See the status with a nice UI
- Manual refresh only (auto-refresh made it angry)

## 🏗️ How It's Organized

```
FreeRTOS Tasks (The Chaos):
├── Serial (Priority 26) - Your USB connection
├── Watchdog (Priority 27) - Judges everything  
├── WiFi Background (Priority 25) - Talks to WiFi chip
├── HTTP Server (Priority 5) - Handles web requests
└── WiFi Init (Priority 5) - Starts the AP, then dips
```

Each task does its thing. Sometimes they play nice. Sometimes they don't.

## � The Problems (Why You're Here)

### Problem #1: Serial Breaks When WiFi Starts
- **What happens:** You plug it in, start provisioning, then enable WiFi → EVERYTHING BREAKS
- **Why:** WiFi initialization steals CPU time from serial task
- **Current fix:** Wait 60 seconds before enabling WiFi so provisioning can finish
- **Better fix:** TODO (we're working on it)

**TL;DR:** Do provisioning FIRST, THEN WiFi is okay.

### Problem #1.5: Garbage Output During Provisioning (The Real Issue)
- **What you see:** Corrupted binary data mixed with partial debug messages
- **Example:**
```
�YVOS����fCOO�f=p$
*Sent T2H_ECDH_SHARE (host-initiated ECDH)
J��y�����)ۘ%�EU
```
- **Why it happens:** Serial ISR receiving data while main protocol handler is processing
- **Root cause:** No proper frame synchronization - data gets interleaved
- **This means:** Protocol state machine is running during USB ISR, causing data corruption
- **Impact:** ECDH exchange fails, provisioning breaks completely

**TL;DR:** Serial + WiFi task switching breaks the protocol. Need to disable WiFi polling DURING provisioning.

### Problem #2: macOS Hates Unplugging It
- **What happens:** Unplug/replug a few times → macOS loses the device completely
- **Why:** macOS USB driver gets confused (not our problem but we suffer)
- **How to fix it:** Restart your Mac (bruh)
- **Pro tip:** Just leave it plugged in. Works fine if you don't touch it.

**TL;DR:** Regular Pico 2 doesn't have this. WiFi chip adds drama.

### Problem #3: API Info Crashes
- **What it tried to do:** Read temperature sensor
- **What actually happened:** Pico went to another dimension 🌀
- **Status:** Removed from API
- **Can we bring it back?** Maybe, if we rewrite it

**TL;DR:** Just don't ask for it.

## 🔨 Build It

```bash
cd build
cmake ..
make -j4
picotool load pico_project_template.uf2 -u -f
```

Standard procedure. Nothing fancy.

## 🧪 Test It

### Test via USB Serial
```bash
screen /dev/tty.usbmodem* 115200
# See debug output, watch provisioning happen
```

### Test via WiFi
Connect to `MASTR-Token` WiFi, then:

```bash
# Quick check - is it alive?
curl http://192.168.4.1/api/ping

# Check provisioning status
curl http://192.168.4.1/api/status

# Open web interface
open http://192.168.4.1
```

## � Stats

- **Firmware Size:** 463 KB (still fits in 4 MB)
- **RAM Used:** 138 KB (we got room)
- **Bugs:** Still has some but we shipped it anyway

## 🎯 What's Next

1. **FIX: Disable WiFi polling during provisioning** 
   - Add `provisioning_active` flag to protocol_state
   - Set to `true` at boot, `false` when reaching state 0x40
   - Modify `wifi_background_task()` to skip `cyw43_arch_poll()` if provisioning_active
   - This prevents task switching during ECDH key exchange

2. **Test full flow:** Provision → then WiFi polling starts → both work together

3. **Maybe fix `/api/info`** → Temperature reading without crashing

4. **macOS USB drama** → Not much we can do, macOS issue

---

Made on a Pico 2 W. Works most of the time. That's a win in my book. ✌️ 