#include <stdio.h>
#include <string.h>
#include "serial.h"
#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "FreeRTOS.h"
#include "task.h"

// Add binary info
bi_decl(bi_program_name("MASTR"));
bi_decl(bi_program_description("Mutual Attested Secure Token for Robotics"));
bi_decl(bi_program_version_string("0.0.2"));

void print_board_info() {
    printf("Pico Project Template\n");

#if defined(PICO_BOARD)
    printf("Board: %s\n", PICO_BOARD);
#else
    printf("Board: Not specified\n");
#endif

#if defined(PICO_TARGET_NAME)
    printf("SoC: %s\n", PICO_TARGET_NAME);
#else
    printf("SoC: Not specified\n");
#endif

#if defined(CYW43_ARCH_THREADSAFE_BACKGROUND)
    printf("WiFi support: Enabled\n");
#else
    printf("WiFi support: Disabled\n");
#endif
}

// FreeRTOS task for processing serial data
void serial_task(void *params) {
    (void)params;  // Unused parameter
    
    while (true) {
        process_serial_data();
        // Small delay to yield to other tasks
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

void mainloop(){
    while (true) {
        process_serial_data();
    }
}

int main() {
    stdio_init_all();
    
    print_board_info();
    printf("FreeRTOS Integration Test\n");
    
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
    
    // Start the FreeRTOS scheduler
    printf("Starting FreeRTOS scheduler...\n");
    vTaskStartScheduler();
    
    // Should never reach here
    printf("ERROR: Scheduler failed to start!\n");
    while (1) {
        tight_loop_contents();
    }
    
    return 0;
}
