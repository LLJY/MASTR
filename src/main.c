#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "pico/time.h"
#include "hardware/i2c.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cryptoauthlib.h"
#include "serial.h"
#include "constants.h"
#include "protocol.h"
#include "net/wifi_ap.h"
#include "net/http/http_server.h"
#include "cpu_monitor.h"
#include "crypto.h"

// Add binary info
bi_decl(bi_program_name("MASTR"));
bi_decl(bi_program_description("Mutual Attested Secure Token for Robotics"));
bi_decl(bi_program_version_string("0.0.3"));

void print_board_info() {
    // All debug output goes through DEBUG_MSG protocol
    print_dbg("MASTR - Mutual Attested Secure Token for Robotics\n");

#if defined(PICO_BOARD)
    print_dbg("Board: %s\n", PICO_BOARD);
#else
    print_dbg("Board: Not specified\n");
#endif

#if defined(PICO_TARGET_NAME)
    print_dbg("SoC: %s\n", PICO_TARGET_NAME);
#else
    print_dbg("SoC: Not specified\n");
#endif

#if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    print_dbg("WiFi support: Enabled\n");
#else
    print_dbg("WiFi support: Disabled\n");
#endif
}

// FreeRTOS task for processing serial data
void serial_task(void *params) {
    (void)params;  // Unused parameter
    
    while (true) {
        serial_process_data();
        // process_serial_data now blocks on semaphore, no need for delay
    }
}

// Enhanced watchdog task - monitors session timeout, system health, and AP stability
void watchdog_task(void *params) {
    (void)params;  // Unused parameter
    
    print_dbg("Enhanced watchdog task started\n");
    
    // System health monitoring variables
    static uint32_t last_heap_check = 0;
    static uint32_t heap_warning_count = 0;
    static uint32_t task_count_baseline = 0;
    static bool baseline_set = false;
    
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));  // Check every 1 second
        
        g_protocol_state.last_watchdog_check = time_us_64();
        uint32_t current_time_ms = to_ms_since_boot(get_absolute_time());
        
        // === SYSTEM HEALTH MONITORING ===
        
        // 1. Memory health check (every 5 seconds)
        if (current_time_ms - last_heap_check > 5000) {
            size_t free_heap = xPortGetFreeHeapSize();
            size_t min_free_ever = xPortGetMinimumEverFreeHeapSize();
            
            // Warning if free heap drops below 4KB or minimum ever below 2KB
            if (free_heap < 4096 || min_free_ever < 2048) {
                heap_warning_count++;
                print_dbg("WATCHDOG: Low memory warning - Free: %u bytes, Min ever: %u bytes (count: %u)\n", 
                    (unsigned)free_heap, (unsigned)min_free_ever, heap_warning_count);
                
                // If persistent memory issues, force garbage collection
                if (heap_warning_count > 3) {
                    print_dbg("WATCHDOG: Forcing task cleanup due to persistent memory pressure\n");
                    // Could add task cleanup logic here if needed
                }
            } else if (heap_warning_count > 0) {
                heap_warning_count = 0; // Reset counter when memory recovers
            }
            
            last_heap_check = current_time_ms;
        }
        
        // 2. Task count monitoring (detect task leaks)
        UBaseType_t current_task_count = uxTaskGetNumberOfTasks();
        if (!baseline_set) {
            task_count_baseline = current_task_count;
            baseline_set = true;
            print_dbg("WATCHDOG: Task baseline set to %u tasks\n", task_count_baseline);
        } else if (current_task_count > task_count_baseline + 3) {
            print_dbg("WATCHDOG: Task count increased significantly - Current: %u, Baseline: %u\n", 
                current_task_count, task_count_baseline);
        }
        
        // 3. WiFi AP Health Monitoring (every 10 seconds)
        static uint32_t last_wifi_check = 0;
        static uint32_t wifi_failure_count = 0;
        
        if (current_time_ms - last_wifi_check > 10000) {
            // Check if AP is still operational
            bool ap_active = wifi_ap_is_active();
            if (!ap_active) {
                wifi_failure_count++;
                print_dbg("WATCHDOG: WiFi AP failure detected (count: %u)\n", wifi_failure_count);
                
                // Try to restart AP after 3 consecutive failures
                if (wifi_failure_count >= 3) {
                    print_dbg("WATCHDOG: Attempting WiFi AP recovery...\n");
                    wifi_ap_restart();
                    wifi_failure_count = 0; // Reset counter after restart attempt
                }
            } else {
                wifi_failure_count = 0; // Reset counter when AP is healthy
            }
            
            last_wifi_check = current_time_ms;
        }
        
        // 4. HTTP Server Health Check (every 15 seconds)
        static uint32_t last_http_check = 0;
        
        if (current_time_ms - last_http_check > 15000) {
            // Check for HTTP server responsiveness
            uint32_t active_connections = http_get_active_connections();
            if (active_connections > 10) {
                print_dbg("WATCHDOG: High HTTP connection count: %u (potential DoS)\n", active_connections);
            }
            
            last_http_check = current_time_ms;
        }
        
        // Skip session monitoring if in permanent halt state
        if (g_protocol_state.in_halt_state) {
            continue;
        }
        
        // === SESSION TIMEOUT MONITORING ===
        // Only monitor timeout when in runtime state (0x40)
        if (g_protocol_state.current_state == 0x40) {
            if (!protocol_is_session_valid()) {
                print_dbg("WATCHDOG: Session timeout detected - triggering re-attestation\n");
                protocol_trigger_reattestation();
            }
        }
    }
}

// Idle monitor removed (tick-based idle accounting deprecated)

int main() {
    stdio_init_all();
    
    print_board_info();
    
    // Initialize cryptoauthlib (HAL will initialize I2C hardware)
    ATCAIfaceCfg cfg = {
        .iface_type = ATCA_I2C_IFACE,
        .devtype = ATECC608A,
        .atcai2c.address = 0x6A,     // 8-bit format (0x35 << 1) - NEW CHIP!
        .atcai2c.bus = 0,
        .atcai2c.baud = 100000,      // 100kHz for reliability
        .wake_delay = 1500,
        .rx_retries = 20
    };
    
    ATCA_STATUS status = atcab_init(&cfg);
    if (status != ATCA_SUCCESS) {
        // we cannot continue, panic.
        
    }
    
    // Initialize cryptographic subsystem
    if (!crypto_init()) {
        print_dbg("WARNING: Crypto subsystem init failed\n");
    }
        
    // Create the serial processing task
    // OPTIMIZED Priority hierarchy for stability (configMAX_PRIORITIES = 32):
    //   31 (MAX-1): FreeRTOS Timer Service Task
    //   28:         Watchdog (critical system monitoring)
    //   26:         Serial Protocol (attestation critical)
    //   24:         WiFi Background (driver stability) 
    //   20:         Crypto/Host pubkey tasks
    //   15:         HTTP API tasks
    //   10:         WiFi Init (deferred startup)
    //   5:          Background maintenance
    //   0:          Idle task
    //
    // Note: Serial is interrupt-driven, high priority prevents web server blocking.
    // Watchdog gets highest priority to ensure system monitoring is never blocked.
    TaskHandle_t serial_task_handle;
    BaseType_t serial_result = xTaskCreate(
        serial_task,
        "Serial",                           // Task name
        DEFAULT_STACK_SIZE + 512,           // Larger stack for stability (words, not bytes)
        NULL,                               // Parameters
        26,                                 // Priority 26 (high, but below watchdog)
        &serial_task_handle                 // Task handle
    );
    
    if (serial_result != pdPASS || serial_task_handle == NULL) {
        print_dbg("FATAL: Failed to create Serial task - system cannot continue\n");
        // System cannot function without serial task
        while (1) { tight_loop_contents(); }
    }
    
    // Create the enhanced watchdog task (HIGHEST priority for system monitoring)
    TaskHandle_t watchdog_task_handle;
    BaseType_t watchdog_result = xTaskCreate(
        watchdog_task,
        "Watchdog",                         // Task name
        DEFAULT_STACK_SIZE + 256,           // Extra stack for monitoring logic
        NULL,                               // Parameters
        28,                                 // Highest user priority (below timer service)
        &watchdog_task_handle               // Task handle
    );
    
    if (watchdog_result != pdPASS || watchdog_task_handle == NULL) {
        print_dbg("FATAL: Failed to create Watchdog task - system stability compromised\n");
        // System can continue but without monitoring - proceed with caution
    }
    
    // Initialize serial subsystem with task handle for notifications
    serial_init(serial_task_handle);

    // Initialize protocol state
    g_protocol_state.protocol_begin_timestamp = time_us_64();
    g_protocol_state.current_state = H2T_ECDH_SHARE;  // Start at ECDH state (0x20)
    
    // Initialize session management
    g_protocol_state.is_encrypted = false;         // Encryption disabled until first ECDH
    g_protocol_state.session_valid = false;        // No valid session yet
    g_protocol_state.session_start_timestamp = 0;
    g_protocol_state.session_timeout_ms = 30000;   // Default 30 second timeout
    g_protocol_state.last_watchdog_check = 0;
    g_protocol_state.in_halt_state = false;        // Not in halt state

    // TODO check if the token has been provisioned, if not, do special magic to
    // start the web server in a special admin mode.

    // WiFi initialization with LONG delay
    // IMPORTANT: WiFi initialization is causing serial provisioning issues
    // We start WiFi but NOT the background polling task
    if (!wifi_ap_init()) {
        print_dbg("WARNING: WiFi subsystem preparation failed\n");
    } else {
        // Enable WiFi background task (required for stable lwIP & driver event processing)
        // Higher priority than before for better WiFi stability
        BaseType_t wifi_bg_result = xTaskCreate(
            wifi_background_task,
            "WiFi-BG",
            DEFAULT_STACK_SIZE + 512,       // Larger stack for lwIP stability
            NULL,
            24,                             // Priority 24 (high, for driver stability)
            NULL
        );
        
        if (wifi_bg_result != pdPASS) {
            print_dbg("ERROR: Failed to create WiFi background task - AP may be unstable\n");
        }
        
        // Create WiFi AP initialization task (lower priority, deferred startup)
        // Waits for system to stabilize before starting AP
        BaseType_t wifi_init_result = xTaskCreate(
            wifi_ap_init_task,
            "WiFi-Init",
            DEFAULT_STACK_SIZE + 256,       // Extra stack for initialization
            NULL,
            10,                             // Priority 10 (medium-low, deferred)
            NULL
        );
        
        if (wifi_init_result != pdPASS) {
            print_dbg("ERROR: Failed to create WiFi init task - AP will not start\n");
        }
    }

    // Idle monitor task removed

    // Start the FreeRTOS scheduler
    vTaskStartScheduler();
    
    // Should never reach here
    print_dbg("ERROR: Scheduler failed to start!\n");
    while (1) {
        tight_loop_contents();
    }
    
    return 0;
}
