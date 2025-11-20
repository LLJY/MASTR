#ifndef CONSTANTS_H
#define CONSTANTS_H

#define MAX_PAYLOAD_SIZE 256

#define SOF_BYTE 0x7F
#define EOF_BYTE 0x7E
#define ESC_BYTE 0x7D

#define ESC_SUB_SOF 0x5F // Replaces a SOF byte in the data
#define ESC_SUB_EOF 0x5E // Replaces an EOF byte in the data
#define ESC_SUB_ESC 0x5D // Replaces an ESC byte in the data

#if defined(PICO_RP2350) || defined(PICO_BOARD_PICO2) || defined(PICO_BOARD_PICO2_W)
#define DEFAULT_STACK_SIZE 2048
#else
#define DEFAULT_STACK_SIZE 1024
#endif 

// ============================================================================
// Branch Prediction Hints (POSIX-style, mirrors Linux kernel)
// ============================================================================
#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

// ============================================================================
// Watchdog Constants (main.c)
// ============================================================================
#define WATCHDOG_HEAP_CHECK_INTERVAL_MS     5000
#define HEAP_WARNING_THRESHOLD_BYTES        4096
#define HEAP_MIN_EVER_THRESHOLD_BYTES       2048
#define HEAP_WARNING_PERSISTENT_COUNT       3
#define WATCHDOG_WIFI_CHECK_INTERVAL_MS     10000
#define WIFI_FAILURE_RESTART_THRESHOLD      3
#define WATCHDOG_HTTP_CHECK_INTERVAL_MS     15000
#define HTTP_HIGH_CONNECTION_THRESHOLD      10

#endif