/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_key_config.h"
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Configuration for initializing a PSA TLS client backed by ATECC608A.
 */
typedef struct {
    uint8_t slot_id;              /**< ATECC key slot (default 0) */
    const uint8_t *device_cert;   /**< User-provided DER cert, or NULL to auto-read from TNG */
    size_t device_cert_len;       /**< Length of user-provided cert, 0 for auto-read */
} esp_atca_psa_client_config_t;

/**
 * @brief Context holding PSA key handle, certificate, and esp-tls key config.
 *
 * After a successful call to esp_atca_init_psa_client(), pass key_config
 * to esp-tls (e.g. via NetworkContext_t::client_key) and device_cert /
 * device_cert_len as the client certificate.
 */
typedef struct {
    esp_key_config_t key_config;  /**< Ready to pass to esp-tls via client_key */
    const uint8_t *device_cert;   /**< DER certificate pointer */
    size_t device_cert_len;       /**< Certificate length in bytes */
    psa_key_id_t psa_key_id;     /**< PSA key id, used internally for cleanup */
} esp_atca_psa_client_ctx_t;

/**
 * @brief Initialise the ATECC608A hardware, read the device certificate,
 *        import the private-key reference into PSA Crypto and populate an
 *        esp_key_config_t that esp-tls can consume directly.
 *
 * @param[out] ctx    Context to populate. Must not be NULL.
 * @param[in]  config Configuration. Pass NULL for all-defaults (slot 0, TNG cert).
 *
 * @return
 *  - ESP_OK on success
 *  - ESP_ERR_INVALID_ARG if ctx is NULL
 *  - ESP_FAIL on ATECC / PSA failure (details logged)
 */
esp_err_t esp_atca_init_psa_client(esp_atca_psa_client_ctx_t *ctx,
                                   const esp_atca_psa_client_config_t *config);

/**
 * @brief Destroy the PSA key, release ATECC hardware and zero the context.
 *
 * Safe to call on a zero-initialised or already-freed context.
 *
 * @param[in,out] ctx Context previously initialised by esp_atca_init_psa_client().
 */
void esp_atca_free_psa_client(esp_atca_psa_client_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
