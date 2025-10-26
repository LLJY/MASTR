/*
 * Copyright (c) 2025 Lucas Lee Jing Yi
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "atca_hal.h"
#include "hal_pico_i2c.h"
#include "atca_device.h"
#include "calib_command.h"
#include "FreeRTOS.h"
#include "task.h"

#define I2C_SDA_PIN 0
#define I2C_SCL_PIN 1

// Maximum execution time for ATECC608 commands (in milliseconds)
// Must accommodate slowest operations: GENKEY (653ms), SELFTEST (625ms)
#define ATCA_EXEC_MAX_TIME_MS 1000

// Convert CryptoAuthLib 8-bit I2C address to Pico SDK 7-bit address
#define ATCA_TO_PICO_I2C_ADDR(addr) ((addr) >> 1)

uint32_t exec_max_time_ms(ATCADeviceType device_type)
{
    (void)device_type;
    return ATCA_EXEC_MAX_TIME_MS;
}

void pico_delay_ms(uint32_t ms)
{
    if (ms == 0)
    {
        return;
    }

    // Calculate the number of ticks required for the delay
    TickType_t ticks_to_wait = pdMS_TO_TICKS(ms);

    if (ticks_to_wait == 0)
    {
        // The requested delay is less than one RTOS tick.
        // We MUST use a busy-wait to guarantee the delay.
        sleep_ms(ms);
    }
    else
    {
        // The delay is long enough to use the RTOS scheduler.
        // This blocks the *task* (cooperatively) but not the *CPU*.
        vTaskDelay(ticks_to_wait);
    }
}

void pico_delay_us(uint32_t us)
{
    sleep_us(us);
}

// HAL helper functions required by CryptoAuthLib
void* hal_malloc(size_t size)
{
    return malloc(size);
}

void hal_free(void* ptr)
{
    free(ptr);
}

void hal_delay_ms(uint32_t ms)
{
    pico_delay_ms(ms);
}

void hal_delay_us(uint32_t us)
{
    sleep_us(us);
}

ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg *cfg)
{
    if (!cfg) {
        return ATCA_BAD_PARAM;
    }
    
    // Initialize I2C hardware
    i2c_init(i2c0, cfg->atcai2c.baud);
    gpio_set_function(I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA_PIN);
    gpio_pull_up(I2C_SCL_PIN);
    
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    
    uint8_t buffer[txlength + 1];
    buffer[0] = word_address;
    if (txlength > 0 && txdata != NULL) {
        memcpy(&buffer[1], txdata, txlength);
    }
    
    uint8_t i2c_addr = ATCA_TO_PICO_I2C_ADDR(cfg->atcai2c.address);
    int ret = i2c_write_blocking(i2c0, i2c_addr, buffer, txlength + 1, false);
    
    // Add delay after idle/sleep commands
    if ((word_address == 0x01 || word_address == 0x02) && ret == txlength + 1) {
        sleep_ms(1);
    }
    
    return (ret == txlength + 1) ? ATCA_SUCCESS : ATCA_TX_FAIL;
}

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    if (!rxdata || !rxlength || *rxlength == 0) return ATCA_BAD_PARAM;

    uint16_t rxdata_max_size = *rxlength;
    int retries = cfg->rx_retries;
    uint8_t i2c_addr = ATCA_TO_PICO_I2C_ADDR(cfg->atcai2c.address);
    
    *rxlength = 0;
    
    // For polling reads (checking if data ready)
    if (rxdata_max_size == 1) {
        for (int i = 0; i < retries; i++) {
            int ret = i2c_read_blocking(i2c0, i2c_addr, rxdata, 1, false);
            if (ret == 1) {
                *rxlength = 1;
                return ATCA_SUCCESS;
            }
            sleep_us(1000);
        }
        return ATCA_RX_FAIL;
    }
    
    // Data read
    int ret = i2c_read_blocking(i2c0, i2c_addr, rxdata, rxdata_max_size, false);
    
    if (ret != rxdata_max_size) {
        return ATCA_RX_FAIL;
    }
    
    *rxlength = ret;
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t response[4] = { 0 };
    uint8_t device_addr = ATCA_TO_PICO_I2C_ADDR(cfg->atcai2c.address);
    
    // Send SDA low pulse to address 0x00 (wake condition)
    uint8_t wake_data = 0x00;
    i2c_write_blocking(i2c0, 0x00, &wake_data, 1, false);
    
    // Wait for device to wake up (tWHI)
    sleep_us(cfg->wake_delay);
    
    // Read 4-byte wake response: 0x04 0x11 0x33 0x43
    for (int attempt = 0; attempt < cfg->rx_retries; attempt++) {
        if (attempt > 0) {
            sleep_us(1000);
        }
        
        int ret = i2c_read_blocking(i2c0, device_addr, response, 4, false);
        
        if (ret == 4) {
            // Validate: should be 0x04 0x11 0x33 0x43
            if (response[0] == 0x04 && response[1] == 0x11 && 
                response[2] == 0x33 && response[3] == 0x43) {
                return ATCA_SUCCESS;
            }
        }
    }
    
    return ATCA_WAKE_FAILED;
}

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t buffer[1] = { 0x02 };
    uint8_t i2c_addr = ATCA_TO_PICO_I2C_ADDR(cfg->atcai2c.address);
    
    int ret = i2c_write_blocking(i2c0, i2c_addr, buffer, 1, false);
    
    if (ret == 1) {
        sleep_ms(1);
        return ATCA_SUCCESS;
    }
    
    return ATCA_TX_FAIL;
}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t buffer[1] = { 0x01 };
    uint8_t i2c_addr = ATCA_TO_PICO_I2C_ADDR(cfg->atcai2c.address);
    
    int ret = i2c_write_blocking(i2c0, i2c_addr, buffer, 1, false);
    
    if (ret == 1) {
        sleep_ms(1);
        return ATCA_SUCCESS;
    }
    
    return ATCA_TX_FAIL;
}

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    i2c_deinit(i2c0);
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;
    
    switch (option) {
        case ATCA_HAL_CONTROL_WAKE:
            return hal_i2c_wake(iface);
            
        case ATCA_HAL_CONTROL_IDLE:
            return hal_i2c_idle(iface);
            
        case ATCA_HAL_CONTROL_SLEEP:
            return hal_i2c_sleep(iface);
            
        case ATCA_HAL_CHANGE_BAUD:
            // Baud rate changes not supported in this implementation
            return ATCA_SUCCESS;
            
        default:
            return ATCA_UNIMPLEMENTED;
    }
}
