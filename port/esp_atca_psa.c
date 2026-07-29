/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sdkconfig.h"

/* The PSA opaque driver interface (esp_key_config.h, psa/crypto.h) only exists
 * on ESP-IDF >= 6.0; the guard also keeps this file empty on older versions. */
#if defined(CONFIG_MBEDTLS_SECURE_ELEMENT_DRIVER_ENABLED)

#include "esp_atca_psa.h"

#include <string.h>
#include "esp_log.h"
#include "cryptoauthlib.h"
#include "tng_atcacert_client.h"
#include "psa_crypto_driver_secure_element.h"
#include "psa_crypto_driver_secure_element_contexts.h"

static const char *TAG = "esp_atca_psa";

/* Static buffer for TNG device certificate (DER) */
static uint8_t s_device_cert_der[1024];

/*
 * ATECC608A callback implementations for the SE ECDSA PSA driver
 */

static psa_status_t atecc_sign_cb(uint8_t slot_id, const uint8_t *hash, size_t hash_len,
                                  uint8_t *sig, size_t sig_size, size_t *sig_len)
{
    if (hash_len != 32 || sig_size < 64) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ATCA_STATUS status = atcab_sign(slot_id, hash, sig);
    if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "atcab_sign failed: 0x%02x", status);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    *sig_len = 64;
    return PSA_SUCCESS;
}

static psa_status_t atecc_export_pubkey_cb(uint8_t slot_id, uint8_t *pubkey,
                                           size_t pubkey_size, size_t *pubkey_len)
{
    if (pubkey_size < 64) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ATCA_STATUS status = atcab_get_pubkey(slot_id, pubkey);
    if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "atcab_get_pubkey failed: 0x%02x", status);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    *pubkey_len = 64;
    return PSA_SUCCESS;
}

static psa_status_t atecc_verify_cb(const uint8_t *hash, size_t hash_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const uint8_t *pubkey, size_t pubkey_len,
                                    bool *is_verified)
{
    if (hash_len != 32 || sig_len != 64 || pubkey_len != 64) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    bool verified = false;
    ATCA_STATUS status = atcab_verify_extern(hash, sig, pubkey, &verified);
    if (status != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "atcab_verify_extern failed: 0x%02x", status);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    *is_verified = verified;
    return PSA_SUCCESS;
}

static const secure_element_callbacks_t s_atecc_callbacks = {
    .sign = atecc_sign_cb,
    .export_pubkey = atecc_export_pubkey_cb,
    .verify = atecc_verify_cb,
    .algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_256),
    .key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
    .key_bits = 256,
};

esp_err_t esp_atca_init_psa_client(esp_atca_psa_client_ctx_t *ctx,
                                   const esp_atca_psa_client_config_t *config)
{
    if (ctx == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(ctx, 0, sizeof(*ctx));

    /* Use defaults when config is NULL */
    uint8_t slot_id = 0;
    const uint8_t *user_cert = NULL;
    size_t user_cert_len = 0;

    if (config != NULL) {
        slot_id = config->slot_id;
        user_cert = config->device_cert;
        user_cert_len = config->device_cert_len;
    }

    /* 1. Initialise ATECC608A hardware */
    ATCA_STATUS atca_ret = atcab_init(&cfg_ateccx08a_i2c_default);
    if (atca_ret != ATCA_SUCCESS) {
        ESP_LOGE(TAG, "atcab_init failed: 0x%02x", atca_ret);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ATECC608A initialised");

    /* 2. Obtain device certificate */
    if (user_cert != NULL && user_cert_len > 0) {
        ctx->device_cert = user_cert;
        ctx->device_cert_len = user_cert_len;
    } else {
        size_t cert_size = sizeof(s_device_cert_der);
        int cert_ret = tng_atcacert_read_device_cert(s_device_cert_der, &cert_size, NULL);
        if (cert_ret != ATCACERT_E_SUCCESS) {
            ESP_LOGE(TAG, "tng_atcacert_read_device_cert failed: 0x%04x", cert_ret);
            atcab_release();
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Read TNG device certificate (%d bytes DER)", (int)cert_size);
        ctx->device_cert = s_device_cert_der;
        ctx->device_cert_len = cert_size;
    }

    /* 3. Initialise PSA Crypto (idempotent) */
    psa_status_t psa_ret = psa_crypto_init();
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed: %d", (int)psa_ret);
        atcab_release();
        return ESP_FAIL;
    }

    /* 4. Register ATECC608A callbacks with the SE ECDSA driver */
    psa_ret = secure_element_register_callbacks(&s_atecc_callbacks);
    if (psa_ret != PSA_SUCCESS && psa_ret != PSA_ERROR_BAD_STATE) {
        /* PSA_ERROR_BAD_STATE means callbacks already registered (OK) */
        ESP_LOGE(TAG, "secure_element_register_callbacks failed: %d", (int)psa_ret);
        atcab_release();
        return ESP_FAIL;
    }

    /* 5. Import ATECC608 key reference into PSA */
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_lifetime(&key_attr, PSA_KEY_LIFETIME_SECURE_ELEMENT_VOLATILE);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attr, 256);

    secure_element_opaque_key_t opaque_key = {
        .slot_id = slot_id,
    };

    psa_ret = psa_import_key(&key_attr, (const uint8_t *)&opaque_key,
                             sizeof(opaque_key), &ctx->psa_key_id);
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_import_key failed: %d", (int)psa_ret);
        atcab_release();
        return ESP_FAIL;
    }

    /* 6. Populate esp_key_config_t for esp-tls */
    ctx->key_config.source = ESP_KEY_SOURCE_PSA;
    ctx->key_config.psa.key_id = ctx->psa_key_id;

    ESP_LOGI(TAG, "PSA client ready (key_id=0x%08lx, slot=%d)",
             (unsigned long)ctx->psa_key_id, slot_id);
    return ESP_OK;
}

void esp_atca_free_psa_client(esp_atca_psa_client_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->psa_key_id != 0) {
        psa_destroy_key(ctx->psa_key_id);
    }

    atcab_release();
    memset(ctx, 0, sizeof(*ctx));
}

#endif /* CONFIG_MBEDTLS_SECURE_ELEMENT_DRIVER_ENABLED */
