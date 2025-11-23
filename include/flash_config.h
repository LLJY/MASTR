/**
 * @file flash_config.h
 * @brief Flash-based persistent configuration storage for MASTR
 *
 * Stores WiFi password in the last sector of flash memory.
 * Flash operations require ~45ms system freeze (interrupts disabled).
 */

#ifndef FLASH_CONFIG_H
#define FLASH_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Write WiFi password to flash memory
 *
 * WARNING: This function will freeze the system for ~45ms while erasing
 * and programming flash. It coordinates with FreeRTOS and multicore.
 *
 * @param password Password string (max 63 chars)
 * @return true on success, false on failure
 */
bool flash_write_wifi_password(const char *password);

/**
 * Read WiFi password from flash memory
 *
 * This is a fast, non-blocking operation that reads from XIP memory.
 *
 * @param password Buffer to store password
 * @param max_len Maximum length of buffer
 * @return true if valid password found, false if flash is empty
 */
bool flash_read_wifi_password(char *password, size_t max_len);

/**
 * Clear WiFi password from flash memory
 *
 * WARNING: This function will freeze the system for ~45ms while erasing flash.
 *
 * @return true on success, false on failure
 */
bool flash_clear_wifi_password(void);

#endif // FLASH_CONFIG_H
