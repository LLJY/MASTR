# Access Point & HTTP API Architecture

This document explains how the Wi‑Fi Access Point (AP) and embedded HTTP API stack are initialized, how requests flow through the system, and the design decisions taken to improve stability (including the recent changes you requested).

---
## High-Level Overview

Component | Responsibility
--------- | --------------
`wifi_ap.c` | Holds persistent AP configuration, starts/stops/reconfigures AP, background tasks.
`ap_manager.c` | Lower-level AP credential (re)configuration helper (e.g. `reconfigure_access_point`).
`http_server.c` | Minimal single-connection HTTP server built on lwIP `tcp_*` APIs.
`api.c` | Registers REST-style endpoints and implements each handler.
`cpu_monitor.c` | Runtime CPU percentage calculation (used by `/api/cpu`).

Boot sequence (simplified):
1. `main.c` calls `wifi_ap_init()` (lightweight marker, not full CYW43 init).
2. Scheduler starts; `wifi_ap_init_task` runs and calls `wifi_ap_start()` to bring up AP (initially OPEN).
3. `ap_manager` initializes AP stack and calls `http_server_init()`.
4. `api_register_routes()` registers all endpoint handlers.
5. `wifi_background_task` wakes periodically to allow lwIP + Wi‑Fi driver progress.
6. Client connects to AP and issues HTTP requests (curl or browser). Handlers respond and connection closes.

---
## AP Lifecycle & Configuration

### Persistent Password Storage
- `wifi_pass_storage[65]` holds the active passphrase (or empty string for OPEN). This avoids dangling pointers when the password changes.
- `wifi_config.password` always points to this storage.

### Start
`wifi_ap_start(const wifi_ap_config_t *config)` deep-copies the password, sets IP (192.168.4.1), and calls `start_access_point()`.

### Rotate Password
`wifi_ap_rotate_password(new_pass)` updates the persistent buffer then calls `reconfigure_access_point()` (no full teardown). If reconfigure fails:
- Falls back to OPEN (empty password) for recovery.

### Stop
`wifi_ap_stop()` invokes `stop_access_point()` and marks `is_running=false`.

### Claim Flow
- `/api/claim` (in `api.c`) generates a random passphrase (currently 16 characters from [A–Za–z0–9]).
- Sets `g_claimed=true` and starts a one-shot timer (grace period ~750 ms) before applying new credentials via `wifi_ap_rotate_password()`.
- Clients receive JSON with new password and reconnect before AP reconfigures.

---
## Tasks & Priorities (FreeRTOS)

Task | Priority (approx) | Purpose
---- | ------------------ | -------
Serial / Protocol | High (MAX-6) | Handles secure protocol, crypto events.
Watchdog | High (MAX-5) | Monitors session timeout, triggers re-attestation.
WiFi Background (`wifi_background_task`) | High (MAX-7) | Allows lwIP + CYW43 driver housekeeping every 50 ms.
HTTP Server Task (`http_server_task`) | Low (~5) | Currently passive (monitoring); core HTTP I/O is interrupt/callback-driven.
AP Init Task (`wifi_ap_init_task`) | Low (~5) | One-shot start of AP after scheduler boot.

Notes:
- The HTTP server does not require a dedicated worker for each connection; lwIP invokes recv callbacks in the context of its stack processing.
- The background Wi‑Fi task is critical—without its periodic delay loop, driver events and DHCP timeouts can stall, causing intermittent API failures.

---
## HTTP Server Design (`http_server.c`)

### Rationale
The stock lwIP raw TCP interface is used for a tiny, predictable footprint. Earlier instability was traced to closing the TCP connection immediately after queuing writes, occasionally producing client-side errors (curl: Recv failure / connection reset). The updated server defers closure until the data is ACKed.

### Core Structures
```
struct route_entry { const char *path; http_handler_fn handler; };
static route_entry routes[MAX_ROUTES];
static http_state_t g_state; // Single connection state
```
- Single active connection slot to minimize RAM: one `request[1024]` buffer.
- Additional connections are politely closed (not aborted) while busy.

### Flow
1. Accept: `http_accept` -> if free, mark `g_state.in_use=true`, install callbacks.
2. Receive: `http_recv` accumulates data until `\r\n\r\n` (end of headers).
3. Dispatch: `handle_request` matches path against `routes[]` and invokes handler.
4. Respond: Handler calls `http_send_json()` -> `send_response()` writes header/body.
5. Close: `tcp_sent` callback triggers `http_close()` once ACKed.

### Stability Improvements
Change | Benefit
------ | -------
Deferred close (wait for ACK) | Avoids race where client sees truncated or reset connection.
Polite busy handling (close vs abort) | Prevents RST storms under rapid curls.
Removed multi-connection experimental code | Simpler state, fewer edge cases.
Minimal per-request parsing | Keeps latency and RAM usage low.

### Adding Endpoints
```
void api_register_routes(void) {
    http_register("/api/ping", ping_handler);
    http_register("/api/health", health_handler);
    http_register("/api/status", status_handler);
    // ... etc ...
}
```
1. Implement `static void new_handler(struct tcp_pcb *pcb, const char *request)` in `api.c`.
2. Register with `http_register("/api/your_path", new_handler);`.
3. Use `http_send_json(pcb, status_code, json_string);` to respond.

---
## API Layer (`api.c`)

Endpoint | Purpose | Key Operations
-------- | ------- | --------------
`/api/health` | Connectivity probe | Returns `{"ok":true}` quickly.
`/api/ping` | Simple RTT test | Returns `{"message":"pong"}`.
`/api/status` | Device + protocol state | Uptime, provisioning, claim flag.
`/api/network` | AP + DHCP lease info | Enumerates connected MAC/IP pairs.
`/api/ram` | Heap usage snapshot | Total/used/free, percent.
`/api/cpu` | CPU utilization | Uses `cpu_monitor` runtime stats.
`/api/temp` | Internal MCU temp | Averaged ADC samples -> °C.
`/api/claim` | Provisioning password set | Random PSK generation + deferred rotation.

Handler pattern:
1. (Optional) gather metrics/state.
2. Format JSON with `snprintf` into a stack buffer.
3. Call `http_send_json()`.

### Claim Timer Mechanism
- Creates a one-shot FreeRTOS timer (`xTimerCreate`) after responding.
- Timer callback spawns `ap_restart_task` (worker task) to perform password rotation after a grace delay (~750 ms). This avoids resetting the AP before the HTTP response leaves the stack.

---
## CPU & Temperature Metrics

Metric | Source | Notes
------ | ------ | -----
CPU% | `cpu_get_percent()` | Runtime stats only; idle task accounted via FreeRTOS.
Temp | Pico ADC (channel 4) | First sample discarded; 8-sample average; formula 27°C at 0.706V.
RAM | FreeRTOS heap API | `xPortGetFreeHeapSize()` vs `configTOTAL_HEAP_SIZE`.

---
## Error Handling & Fallbacks
Scenario | Behavior
-------- | --------
Failed AP start | Logs error, returns false; higher layer may retry.
Failed password rotate | Falls back to OPEN mode to keep access path alive.
Route not found | Returns 404 JSON consistently.
TCP write failure | Aborts connection to prevent partial/inconsistent response.
Busy server (already serving) | Closes new connection gracefully (no RST).

---
## Known Limitations / Future Enhancements
Item | Description | Possible Improvement
---- | ----------- | -------------------
Single connection slot | Sequential request handling only | Add small pool (2–4) if concurrency needed.
No rate limiting | High-frequency curls may monopolize slot | Lightweight token bucket per handler.
Static JSON formatting | Manual `snprintf` | Consider tiny JSON builder for safety/escaping.
No persistence of claim flag | Lost on reboot | Store claimed state in flash/OTP.
Open AP initial state | Convenience for provisioning | Optionally advertise via captive portal & then lock down.

---
## Quick Reference Cheat Sheet
Action | How
------ | ----
Add endpoint | Implement handler in `api.c`, register in `api_register_routes()`.
Get AP config | `wifi_ap_get_config()->ssid / password`.
Rotate password | `wifi_ap_rotate_password(new_psk)`.
Check claimed state | `g_claimed` (internal to `api.c`).
Probe health | curl `/api/health`.
Restart AP manually | `wifi_ap_rotate_password(current_password)` (no change) or add stop/start wrappers.

---
## Minimal Curl Examples
```
# Connectivity
curl -v http://192.168.4.1/api/health

# Status
curl -s http://192.168.4.1/api/status | jq

# Claim flow
curl -s http://192.168.4.1/api/claim | jq   # then reconnect with returned password after grace period

# Metrics
curl -s http://192.168.4.1/api/cpu
curl -s http://192.168.4.1/api/temp
```

---
## Stability Summary of Recent Changes
Change | Problem Addressed
------ | -----------------
Deferred close via `tcp_sent` | Eliminated intermittent client-side RST during short responses.
Polite busy handling | Prevented abrupt resets under rapid successive curls.
Health endpoint | Provided ultra-light probe to separate transport vs handler latency issues.
Password rotation timer | Ensured `/api/claim` response is delivered before AP reconfiguration.
Runtime-only CPU monitoring | Removed earlier idle tick heuristic that produced 0% or erratic values.

---
## Troubleshooting Tips
Symptom | Check | Action
------- | ----- | ------
Curl sporadic failures | Is `/api/health` stable? | If yes, inspect specific heavy endpoints (ADC, DHCP). Rate-limit them.
Claim response received but reconnection fails | Was grace timer executed? | Verify timer creation and worker task ran; increase grace period.
CPU always 0% | Is `cpu_monitor` initialized? | Ensure runtime stats scaling function compiled and scheduler running.
No clients listed | DHCP leases empty? | Confirm device associated; check Wi‑Fi channel/interference.

---
## Glossary
Term | Meaning
---- | -------
AP | Access Point broadcasting SSID for provisioning.
Grace Period | Delay after claim before applying new password.
lwIP | Lightweight IP stack used for TCP/UDP.
CYW43 | Wi‑Fi chip/driver (Raspberry Pi Pico W). 
Idle Task | FreeRTOS lowest-priority task measuring unused CPU time.

---
## Revision History
Date | Change | Author
---- | ------ | ------
2025-11-09 | Initial architecture doc capturing AP + HTTP design and stability fixes | Generated assistant

---
End of document.
