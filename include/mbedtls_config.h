/**
 * @file mbedtls_config.h
 * @brief Minimal mbedTLS configuration for MASTR project
 * 
 * Optimized for low memory usage on Pico
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// Crypto we need - MINIMAL SET ONLY
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_AES_ENABLED
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_HKDF_C

#endif // MBEDTLS_CONFIG_H
