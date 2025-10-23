#include <stdio.h>    // Must be BEFORE serial.h so printf exists
#include <string.h>
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "hardware/i2c.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cryptoauthlib.h"
#include "serial.h"  // Must be AFTER stdio.h to override printf macro

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
    print_dbg("FreeRTOS Integration Test\n");
    
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
        print_dbg("ATECC608 initialized successfully\n");
    } else {
        print_dbg("WARNING: ATECC608 init failed, status: 0x%02X\n", status);
    }
    
    // Create the serial processing task
    TaskHandle_t serial_task_handle;
    xTaskCreate(
        serial_task,           // Task function
        "Serial",              // Task name
        256,                   // Stack size (words, not bytes)
        NULL,                  // Parameters
        tskIDLE_PRIORITY + 1,  // Priority
        &serial_task_handle    // Task handle
    );
    
    // Initialize serial subsystem with task handle for notifications
    serial_init(serial_task_handle);
    
    // Start the FreeRTOS scheduler
    print_dbg("Starting FreeRTOS scheduler...\n");
    vTaskStartScheduler();
    
    // Should never reach here
    print_dbg("ERROR: Scheduler failed to start!\n");
    while (1) {
        tight_loop_contents();
    }
    
    return 0;
}
