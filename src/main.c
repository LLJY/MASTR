#include <stdio.h>
#include <string.h>
#include "serial.h"
#include "pico/stdlib.h"
#include "pico/binary_info.h"

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

void mainloop(){
    while (true) {
        process_serial_data();
    }
}

int main() {
    stdio_init_all();
    mainloop();
    return 0;
}
