#ifndef HAL_PICO_I2C_H
#define HAL_PICO_I2C_H

#include "atca_hal.h"
#include <stdint.h>
#include <stddef.h>

ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_i2c_post_init(ATCAIface iface);
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
ATCA_STATUS hal_i2c_wake(ATCAIface iface);
ATCA_STATUS hal_i2c_idle(ATCAIface iface);
ATCA_STATUS hal_i2c_sleep(ATCAIface iface);
ATCA_STATUS hal_i2c_release(void *hal_data);

void hal_delay_us(uint32_t delay);
void hal_delay_ms(uint32_t delay);
void* hal_malloc(size_t size);
void hal_free(void* ptr);

#endif // HAL_PICO_I2C_H
