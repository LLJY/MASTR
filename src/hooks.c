#include "FreeRTOS.h"
#include "task.h"

void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName) {
    // Minimal handler: loop forever
    (void)xTask;
    (void)pcTaskName;
    for(;;) {}
}
