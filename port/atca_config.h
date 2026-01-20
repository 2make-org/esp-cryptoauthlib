#pragma once
#include "sdkconfig.h"
/* Cryptoauthlib Configuration File */
#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

#if __has_include("esp_idf_version.h")
#include "esp_idf_version.h"
#endif

/*
This requires the `esp_idf_version.h' to be defined.
*/

#ifdef ESP_IDF_VERSION

#if ESP_IDF_VERSION <= ESP_IDF_VERSION_VAL(4, 3, 1)
#define ATCA_ENABLE_DEPRECATED
#endif

#endif

/* Include HALS */
#define ATCA_HAL_I2C
#define ATCA_USE_RTOS_TIMER 1

/* ATCA_MBEDTLS enables mbedTLS ALT integration for hardware ECDSA.
 * This is only supported on ESP-IDF 5.x (mbedTLS 3.x).
 * For ESP-IDF 6.x+ (mbedTLS 4.x), use CONFIG_MBEDTLS_HARDWARE_ATECC instead. */
#if CONFIG_ATCA_MBEDTLS_ECDSA
#if defined(ESP_IDF_VERSION) && ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(6, 0, 0)
/* mbedTLS 4.x doesn't support the ALT mechanism used by cryptoauthlib */
#warning "ATCA_MBEDTLS_ECDSA is not supported on ESP-IDF 6.x+. Use CONFIG_MBEDTLS_HARDWARE_ATECC instead."
#else
#define ATCA_MBEDTLS
#endif
#endif

//#define ATCA_CA_SUPPORT
/* Included device support */
#define ATCA_ATECC608_SUPPORT

#define ATCA_TNG_LEGACY_SUPPORT
#define ATCA_TFLEX_SUPPORT
#define ATCA_TNGTLS_SUPPORT
#define ATCA_TNGLORA_SUPPORT

#define ATCAC_CERT_ADD_EN 1
#define ATCACERT_COMPCERT_EN 1
/* \brief How long to wait after an initial wake failure for the POST to
 *         complete.
 * If Power-on self test (POST) is enabled, the self test will run on waking
 * from sleep or during power-on, which delays the wake reply.
 */
#ifndef ATCA_POST_DELAY_MSEC
#define ATCA_POST_DELAY_MSEC 25
#endif

#define ATCA_PLATFORM_MALLOC malloc
#define ATCA_PLATFORM_FREE free

#define hal_delay_ms atca_delay_ms
#define ATCA_PRINTF
#endif // ATCA_CONFIG_H
