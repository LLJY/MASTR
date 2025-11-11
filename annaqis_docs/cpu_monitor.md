# CPU Utilization Monitor

This document explains the design, implementation, and usage of the CPU utilization reporting now exposed via the `/api/cpu` endpoint. It complements `docs/cpu_utilization_changes.md` (change log) by providing rationale, data flow, and extension points.

## Purpose

Provide an accurate, low‑overhead measurement of MCU busy time so the web UI and API can display current CPU utilization. The metric answers: "What percentage of elapsed time was spent doing non‑Idle task work over a recent sampling window?"

Formal definition:

```
CPU% = (ΔTotalRuntime - ΔIdleRuntime) / ΔTotalRuntime * 100
```

Where the deltas are taken over the accumulation window maintained internally.

## Components

| File | Role |
|------|------|
| `src/cpu_monitor.c` | Core implementation: idle hook + runtime stats sampling + percent calculation. |
| `include/cpu_monitor.h` | Public declarations (`g_idleTicks`, `cpu_get_percent`). |
| `include/FreeRTOSConfig.h` | Enables `configUSE_IDLE_HOOK` and `configGENERATE_RUN_TIME_STATS`; binds runtime counter macro. |
| `src/net/api/api.c` | Calls `cpu_get_percent()` inside HTTP handler `/api/cpu`. |

## Measurement Methods

1. Runtime Stats (Primary)
   - FreeRTOS maintains a per‑task `ulRunTimeCounter` advanced by `portGET_RUN_TIME_COUNTER_VALUE()`. We mapped this to a 10 kHz timebase (`time_us_64() / 100`) for higher resolution and longer wrap period.
   - We snapshot all task counters using `uxTaskGetSystemState()`, identify Idle task(s) by priority (0) plus name prefix (`IDLE`/`Idle`/`idle`), then accumulate deltas until a minimum window size (~100 ms) is reached to reduce noise.
   - Rounded integer percent returned (0–100). The last valid value is cached so early or invalid calls do not jitter.

2. Tick‑Based Idle Hook (Fallback / Diagnostic)
   - `vApplicationIdleHook()` increments `g_idleTicks` at most once per OS tick (gating prevents over‑counting when Idle task loops multiple times per tick).
   - Although currently the `/api/cpu` path uses runtime stats directly, retaining the idle tick counter aids debugging and allows a rapid fallback if runtime stats become unavailable or are disabled.

## Core Function: `cpu_get_percent()`
High‑level flow:

1. Guard: If scheduler not running or too few tasks (<2), return cached percent.
2. Snapshot: Call `uxTaskGetSystemState()` into a static buffer (size cap = 48 tasks).
3. Accumulate: Sum `ulRunTimeCounter` across tasks; separately sum counters for Idle task(s).
4. Baseline: On first call, store totals and return cached value (establish reference).
5. Delta: Compute `dTotal` and `dIdle`; reject if invalid (zero or `dIdle > dTotal`).
6. Windowing: Accumulate deltas until `acc_total >= MIN_RT_DELTA` (~100 ms at 10 kHz).
7. Compute: `busy = dTotal - dIdle`; rounded percent `(busy * 100 + dTotal/2) / dTotal`.
8. Cache & Return.

Why windowing? Very small runtime deltas (< a few hundred ticks at 10 kHz) produce quantization artifacts and frequent 0% despite brief bursts of work. Aggregating ~100 ms smooths jitter while still feeling responsive.

## Timebase Choice

`time_us_64() / 100` gives:
* Resolution: 100 µs per runtime tick (10 kHz)
* Wrap interval: ~429 seconds at 32‑bit (due to division); acceptable because we operate on small deltas and refresh baselines continually. (If multi‑minute windows become desirable, switch to 64‑bit or lower divisor.)

Benefits vs 1 kHz tick:
* Finer granularity → less rounding error for short windows.
* More stable percent under light load.

## Idle Identification Heuristic

We attempted direct `xTaskGetIdleTaskHandle()` linkage; the build for this target raised an undefined reference, so we reverted to a conservative heuristic:
* Priority `0`
* Name starts with one of: `IDLE`, `Idle`, `idle`

This covers common FreeRTOS Idle task naming. If SMP Idle tasks appear per core, heuristic collects both. For future improvement, once symbol availability is verified, replace with handle‑based matching to avoid false positives if user named another priority‑0 task similarly.

## Rationale & Trade‑offs

| Aspect | Decision | Reason |
|--------|----------|--------|
| Accuracy | Runtime stats primary | Measures actual execution time, independent of tick scheduling patterns. |
| Stability | 100 ms accumulation | Reduces percent flicker under intermittent short tasks. |
| Overhead | Static buffers, no malloc | Avoid fragmentation and ISR context issues. |
| Simplicity | Integer percent only | UI needs coarse metric; fractional adds complexity now. |
| Fallback | Retain idle tick counter | Quick revert path; diagnostic visibility. |

## Failure / Edge Cases

| Case | Behavior |
|------|----------|
| Called before scheduler starts | Returns last cached (often 0). |
| Too few tasks (only Idle) | Returns cached (avoid divide-by-zero or misleading 0). |
| `dTotal == 0` | Returns cached (no passage of runtime). |
| `dIdle > dTotal` | Returns cached (invalid sample; likely race or wrap). |
| Counter wrap between samples | Windows are small; wrap improbable at 10 kHz within 100 ms; if occurs, heuristic treats as invalid delta. |

## API Exposure

Endpoint: `/api/cpu`

Response JSON:
```json
{ "cpu_percent": <integer 0-100> }
```

First call after boot often yields 0% (baseline establishment). Subsequent calls after ≥100 ms produce updated values.

## How to Test

1. Boot device; open serial log.
2. Issue repeated requests with ≥150 ms spacing:
   ```bash
   curl http://192.168.4.1/api/cpu
   ```
3. Observe value remain near 0% when idle.
4. Introduce load (network requests loop, crypto operations, synthetic busy task) and verify percent rises.

## Extension Points

| Enhancement | Outline |
|-------------|---------|
| Fractional Percent | Return tenths: `(busy * 1000 + dTotal/2) / dTotal` then format 1 decimal. |
| Longer Smoothing | Increase `MIN_RT_DELTA` for steadier values under bursty load. |
| Adaptive Window | Grow window if busy < threshold for N consecutive samples. |
| Idle Handle Usage | Replace heuristic once linker provides idle task handle symbol. |
| Multi‑Core Attribution | Sum per core idle handles separately to derive per‑core busy%. |

## Gotchas

* Very lightly loaded system legitimately reports 0% for extended periods—this is expected.
* If runtime stats are disabled (`configGENERATE_RUN_TIME_STATS=0`), `cpu_get_percent()` will freeze at last cached value; fallback path would need re‑enablement of tick geometry (currently trimmed for simplicity).
* Adding high‑frequency tasks can bias short windows; consider widening `MIN_RT_DELTA`.

## Minimal API Contract

Inputs: None (implicit global FreeRTOS state).
Outputs: Integer percent 0–100 (monotonic only between successive valid samples; may repeat).
Error Modes: Returns last cached percent when invalid conditions occur (guards listed above).
Success Criteria: Under load increases above baseline; idle remains near 0%; no crashes or allocations.

## Future Reliability Improvements

1. Verify and integrate `xTaskGetIdleTaskHandleForCore` for SMP idle attribution.
2. Unit test: Inject synthetic counters via a test harness mocking `uxTaskGetSystemState()`. (Requires small abstraction layer.)
3. Optional ring buffer of last N samples for trend rendering without recomputation.

## Summary

The CPU monitor combines FreeRTOS runtime stats with guarded sampling and a modest window to deliver an accurate, low‑jitter utilization percentage. Idle tick tracking remains available for diagnostics. Design favors stability (no dynamic allocation, cached returns on invalid snapshots) and easy extensibility.

---
For the chronological list of code modifications and reasoning during development, see `docs/cpu_utilization_changes.md`.
