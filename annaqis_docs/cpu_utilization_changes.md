# CPU Utilization Implementation: Changes and Verification

This document summarizes all code changes made to implement accurate CPU utilization reporting via `/api/cpu`, plus how to verify the behavior on-device.

## Overview

Goal: Report CPU% as busy time over a recent window using FreeRTOS + Pico SDK. We use two complementary methods:
- Primary: FreeRTOS runtime stats (per-task runtime) to compute Busy vs Idle time.
- Fallback: Idle tick gating (count idle “ticks” vs total ticks) with a small accumulation window to avoid jitter.

CPU% formula: `CPU% = (TotalDelta - IdleDelta) / TotalDelta * 100`

## Files Added / Modified

1. `src/cpu_monitor.c` (NEW)
   - Implements `vApplicationIdleHook()`
     - Increments `g_idleTicks` at most once per OS tick (prevents over-counting idle loop iterations).
   - Adds `cpu_get_percent()` using `uxTaskGetSystemState()`
     - Walks task list and sums Idle task runtime (by name prefix `IDLE`/`Idle` and priority 0).
     - Computes CPU% from runtime deltas.
   - Exposes `g_idleTicks` as a global volatile counter.

2. `include/cpu_monitor.h` (NEW)
   - Declarations for `g_idleTicks` and `cpu_get_percent()` so other modules can use them.

3. `src/net/api/api.c` (MODIFIED)
   - `#include "cpu_monitor.h"`
   - `/api/cpu` handler now:
     - Reads runtime-stats-based CPU% via `cpu_get_percent()` (preferred path).
     - Falls back to tick-delta method using `xTaskGetTickCount()` vs `g_idleTicks`.
     - Accumulates deltas into a short window (default `MIN_WINDOW = 50` ticks ≈ 50ms) to avoid tiny instantaneous windows rounding to 0.
     - Emits detailed debug: `rt` (runtime-stats), `tick_inst` (instant tick-delta), `tick_accum` (accumulated window), raw deltas.

4. `src/main.c` (MODIFIED)
   - `#include "cpu_monitor.h"`
   - Added `idle_monitor_task()` (very low priority): prints every 2 seconds
     - Format: `[MON] tick=<system tick> idle=<idle tick>`
     - Confirms `vApplicationIdleHook()` is running and idle ticks advance.
   - Creates `idle_monitor_task` in `main()`.

5. `include/FreeRTOSConfig.h` (MODIFIED)
   - Leaves `configUSE_IDLE_HOOK = 1` enabled.
   - Keeps `configGENERATE_RUN_TIME_STATS = 1` enabled.
   - Updates run-time counter macros to use high-resolution hardware time:
     - `portGET_RUN_TIME_COUNTER_VALUE() -> (uint32_t)time_us_64()`
     - Header include is guarded with `__has_include` and an extern fallback for toolchains.
   - This improves accuracy of runtime stats vs using ticks.

6. `CMakeLists.txt` (MODIFIED)
   - Ensures `src/cpu_monitor.c` is added to the `pico_project_template` target sources.

## Design Notes

- Idle Hook Gating: FreeRTOS may call `vApplicationIdleHook()` many times per tick. We gate increments to `g_idleTicks` to at most once per OS tick so `idle_delta` can be compared to `total_delta` sensibly.
- Runtime stats is preferred when available, as it measures actual time spent in Idle vs other tasks, independent of tick edges.
- Accumulation window (in `api.c`) avoids 0% due to too-small sampling windows; it aggregates several deltas before reporting a new CPU%.

## What You’ll See in Logs

- Idle monitor (every 2s):
  - Example: `[MON] tick=70012 idle=69961`
  - If `idle` increases nearly 1:1 with `tick`, the system is mostly idle.

- `/api/cpu` debug:
  - Example: `[API] CPU(win)=0% (rt=0%, tick_inst=0%, tick_accum=0%, total_delta=755, idle_delta=755, win_busy=0)`
  - `total_delta == idle_delta` → no busy ticks detected → 0% is correct for that window.

## Why 0% Can Be Correct

- With AP active but little to no traffic, CYW43 offloads Wi‑Fi housekeeping. Your MCU only wakes for occasional lwIP or app work, so most OS ticks end in the Idle task.
- Serial task blocks, watchdog sleeps, and web server is idle unless accessed. The scheduler quickly returns to Idle each tick → effectively 0% busy.

## How to See Non‑Zero CPU%

- Generate traffic/work:
  - Hammer the HTTP endpoint or attach a client that transfers data.
  - Run a temporary busy task that does compute in a loop (I can add one on request).
  - Perform crypto operations repeatedly during the measurement window.
- Tuning options (on request):
  - Lower `MIN_WINDOW` (e.g., 50 → 10 ticks) for faster updates.
  - Report tenths of a percent to reveal very small usage instead of rounding to 0.

## Quick Verification Steps

1. Rebuild and flash firmware.
2. Watch serial output:
   - Confirm `[MON] tick=... idle=...` lines appear and both counts increase.
3. Call `/api/cpu` twice with a delay (≥ 250ms):
   - First call initializes baselines → 0%.
   - Subsequent calls report a value once the accumulation window fills.
4. Apply load (traffic or compute) and observe `rt` and/or accumulated `tick` CPU% increase.

## Acceptance Criteria

- Idle monitor shows increasing `tick` and `idle`.
- `/api/cpu` returns 0% when the device is truly idle (expected).
- `/api/cpu` increases above 0% under traffic or synthetic load.
- Debug logs show consistent deltas and chosen CPU% path (runtime vs tick-accum).

---

If you want me to add a small busy task or reduce the window/enable fractional output, say the word and I’ll patch it immediately so you can validate CPU% rises above 0 during load.
