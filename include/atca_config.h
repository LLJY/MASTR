#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

#include <stdlib.h>

/** \defgroup config Configuration (atca_config.h)
 * \brief Logical device configurations for CryptoAuthLib
   @{ */

#include "pico/stdlib.h"
#include "atca_devtypes.h" // Required for the ATCADeviceType enum definition

/**
 * \brief The I2C address for the ATECC608A.
 * This is the default address. It can be changed in the device's configuration zone.
 */
#define ATCA_I2C_ATECC608A_ADDR     (0x60)

/**
 * \brief This is the HAL specific abstraction for the ATECC608A.
 */
#define ATCA_HAL_I2C

/**
 * \brief Define the logical device configurations.
 * These are the configurations for the ATECC608A device.
 */
#define ATCA_ATECC608A_SUPPORT

/**
 * \brief Enable support for Cryptoauth devices (ECC, SHA families)
 * Required for atcab_wakeup() and other CA device functions
 */
#define ATCA_CA_SUPPORT

/**
 * \brief Define the maximum execution time for the ATECC608A.
 */
uint32_t exec_max_time_ms(ATCADeviceType device_type);

#define ATCA_DRV_EXEC_MAX_TIME      (exec_max_time_ms(ATECC608A))

#endif // ATCA_CONFIG_H
