/**
 * @file mbedtls_config.h
 * @brief Minimal mbedTLS configuration for MASTR project
 *
 * Optimized for low memory usage on Pico
 *
 * Set FORCE_SOFTWARE_SHA256=1 to test software SHA256 on RP2350
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// Crypto we need - MINIMAL SET ONLY
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_AES_ENABLED
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C

#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT

// Uncomment to force software SHA256 on RP2350 for testing
// #define FORCE_SOFTWARE_SHA256 1

#define MBEDTLS_SHA256_C
#define MBEDTLS_HKDF_C

#endif // MBEDTLS_CONFIG_H
