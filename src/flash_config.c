/**
 * @file flash_config.c
 * @brief Flash-based persistent configuration storage implementation
 *
 * Stores WiFi password in the last sector of flash memory.
 * Uses proper multicore coordination and FreeRTOS suspension.
 */

#include "flash_config.h"
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/multicore.h"
#include "FreeRTOS.h"
#include "task.h"
#include "serial.h"
#include <string.h>

// Use last sector of flash for config storage
#define CONFIG_FLASH_OFFSET (PICO_FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE)
#define WIFI_PASSWORD_OFFSET 0
#define PASSWORD_VALID_FLAG_OFFSET 64
#define PASSWORD_VALID_MAGIC 0xAA

bool flash_write_wifi_password(const char *password) {
    if (!password) {
        print_dbg("[Flash] ERROR: NULL password pointer\n");
        return false;
    }

    uint8_t page_buffer[FLASH_PAGE_SIZE];
    memset(page_buffer, 0xFF, FLASH_PAGE_SIZE);

    // Copy password (max 63 bytes + null terminator)
    size_t len = strlen(password);
    if (len > 63) {
        print_dbg("[Flash] WARNING: Password too long, truncating to 63 bytes\n");
        len = 63;
    }

    memcpy(page_buffer + WIFI_PASSWORD_OFFSET, password, len);
    page_buffer[WIFI_PASSWORD_OFFSET + len] = '\0';

    // Set valid flag at byte 64
    page_buffer[PASSWORD_VALID_FLAG_OFFSET] = PASSWORD_VALID_MAGIC;

    print_dbg("[Flash] Writing WiFi password (system will freeze for ~45ms)\n");

    // Correct order per Pico SDK: interrupts first, then multicore lockout
    uint32_t ints = save_and_disable_interrupts();
    multicore_lockout_start_blocking();

    // Erase entire config sector (~45ms)
    flash_range_erase(CONFIG_FLASH_OFFSET, FLASH_SECTOR_SIZE);

    // Program first page with password and flag
    flash_range_program(CONFIG_FLASH_OFFSET, page_buffer, FLASH_PAGE_SIZE);

    // Restore in reverse order: multicore first, then interrupts
    multicore_lockout_end_blocking();
    restore_interrupts(ints);

    print_dbg("[Flash] WiFi password written successfully\n");
    return true;
}

bool flash_read_wifi_password(char *password, size_t max_len) {
    if (!password || max_len == 0) {
        print_dbg("[Flash] ERROR: Invalid password buffer\n");
        return false;
    }

    // Read from XIP memory (fast, non-blocking)
    const uint8_t *flash_data = (const uint8_t *)(XIP_BASE + CONFIG_FLASH_OFFSET);

    // Check valid flag
    if (flash_data[PASSWORD_VALID_FLAG_OFFSET] != PASSWORD_VALID_MAGIC) {
        print_dbg("[Flash] No valid WiFi password found in flash\n");
        return false;
    }

    // Copy password
    strncpy(password, (const char *)(flash_data + WIFI_PASSWORD_OFFSET), max_len - 1);
    password[max_len - 1] = '\0';

    print_dbg("[Flash] WiFi password read from flash (len=%d)\n", strlen(password));
    return true;
}

bool flash_clear_wifi_password(void) {
    print_dbg("[Flash] Clearing WiFi password (system will freeze for ~45ms)\n");

    // Correct order per Pico SDK: interrupts first, then multicore lockout
    uint32_t ints = save_and_disable_interrupts();
    multicore_lockout_start_blocking();

    // Erase config sector
    flash_range_erase(CONFIG_FLASH_OFFSET, FLASH_SECTOR_SIZE);

    // Restore in reverse order: multicore first, then interrupts
    multicore_lockout_end_blocking();
    restore_interrupts(ints);

    print_dbg("[Flash] WiFi password cleared from flash\n");
    return true;
}
