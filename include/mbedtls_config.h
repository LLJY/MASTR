/**
 * @file mbedtls_config.h
 * @brief Minimal mbedTLS configuration for MASTR project
 * 
 * Optimized for low memory usage on Pico
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

// System support
// #define MBEDTLS_HAVE_ASM
// #define MBEDTLS_HAVE_TIME
// #define MBEDTLS_HAVE_TIME_DATE
// #define MBEDTLS_PLATFORM_MS_TIME_ALT

// Platform - use custom allocators to reduce BSS
// #define MBEDTLS_PLATFORM_C
// #define MBEDTLS_PLATFORM_MEMORY

// Crypto we need - MINIMAL SET ONLY
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_AES_ENABLED
// #define MBEDTLS_AES_ROM_TABLES              // Use ROM tables instead of RAM (saves ~8KB RAM)
#define MBEDTLS_CIPHER_C
// #define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
// #define MBEDTLS_SHA256_SMALLER              // Use smaller SHA256 implementation
#define MBEDTLS_HKDF_C

// // Optimize for size
// #define MBEDTLS_MPI_WINDOW_SIZE 1           // Reduce window size for smaller memory
// #define MBEDTLS_MPI_MAX_SIZE 128            // Limit MPI size
// #define MBEDTLS_ECP_MAX_BITS 256            // Only support 256-bit curves

// Disable everything we don't need
// #undef MBEDTLS_CIPHER_MODE_CBC
// #undef MBEDTLS_CIPHER_MODE_CFB
// #undef MBEDTLS_CIPHER_MODE_OFB
// #undef MBEDTLS_CIPHER_MODE_XTS
// #undef MBEDTLS_CIPHER_PADDING_PKCS7
// #undef MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
// #undef MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
// #undef MBEDTLS_CIPHER_PADDING_ZEROS

// Required dependencies
// #define MBEDTLS_ERROR_C

#endif // MBEDTLS_CONFIG_H
