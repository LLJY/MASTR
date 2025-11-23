#include "FreeRTOS.h"
#include "task.h"

void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName) {
    (void)xTask;
    (void)pcTaskName;
    // Note: Cannot safely call print_dbg here as stack may be corrupted
    // System must halt to prevent further corruption
    for(;;) {}
}

void vApplicationMallocFailedHook(void) {
    // Memory allocation failed - system stability compromised
    // Halt system to prevent unpredictable behavior
    for(;;) {}
}
