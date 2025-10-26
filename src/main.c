#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "hardware/i2c.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cryptoauthlib.h"
#include "serial.h"
#include "constants.h"
#include "protocol.h"
#include "crypt.h"

// Add binary info
bi_decl(bi_program_name("MASTR"));
bi_decl(bi_program_description("Mutual Attested Secure Token for Robotics"));
bi_decl(bi_program_version_string("0.0.2"));

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
        process_serial_data();
        // process_serial_data now blocks on semaphore, no need for delay
    }
}

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
    if (status == ATCA_SUCCESS) {
    }
    
    // Initialize cryptographic subsystem
    if (!crypt_init()) {
        print_dbg("WARNING: Crypto subsystem init failed\n");
    }
        
    // Create the serial processing task
    // Priority hierarchy relative to (configMAX_PRIORITIES = 32):
    //   31 (MAX-1): Timer task (FreeRTOS system)
    //   ~20-25:     Critical protocol/crypto tasks
    //   ~10-15:     Web server
    //   ~5:         Background tasks
    //   0:          Idle task
    //
    // Note: Serial is interrupt-driven, so it wakes immediately when data arrives.
    // High priority ensures protocol processing isn't blocked by web server.
    TaskHandle_t serial_task_handle;
    xTaskCreate(
        serial_task,                        
        "Serial",                           // Task name
        DEFAULT_STACK_SIZE,                 // Stack size (words, not bytes)
        NULL,                               // Parameters
        configMAX_PRIORITIES - 6,           // Priority
        &serial_task_handle                 // Task handle
    );
    
    // Initialize serial subsystem with task handle for notifications
    serial_init(serial_task_handle);

    // replace with protocol init function
    protocol_state.protocol_begin_timestamp = time_us_64();

    // init protocol by starting it at 0x20 (the correct initial state)
    protocol_state.current_state = H2T_ECDH_SHARE;

    // TODO check if the token has been provisioned, if not, do special magic to
    // start the web server in a special admin mode.

    // Start the FreeRTOS scheduler
    vTaskStartScheduler();
    
    // Should never reach here
    print_dbg("ERROR: Scheduler failed to start!\n");
    while (1) {
        tight_loop_contents();
    }
    
    return 0;
}
