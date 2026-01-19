/*
 * atecc608a_ecdsa example
 *
 * This example demonstrates ECDSA sign/verify operations using an ATECC608
 * secure element. It supports two integration methods:
 *
 * 1. Direct CryptoAuthLib APIs (atcab_sign, atcab_verify_extern, etc.)
 *    - Works on all ESP-IDF versions including 6.x+
 *    - Recommended approach
 *
 * 2. mbedTLS ALT integration (MBEDTLS_ECDSA_SIGN_ALT)
 *    - Uses hardware acceleration through mbedTLS function replacements
 *    - Works with ESP-IDF v5.x and earlier (NOT compatible with mbedtls 4.x)
 *
 * SPDX-FileCopyrightText: 2006-2016 ARM Limited, All Rights Reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * SPDX-FileContributor: 2015-2025 Espressif Systems (Shanghai) CO LTD
 */

/* System Includes*/
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"

/* Cryptoauthlib includes */
#include "cryptoauthlib.h"

/* mbedTLS version check */
#include "mbedtls/version.h"

/*
 * mbedTLS includes - only available in mbedtls < 4.x
 * In ESP-IDF 6.x+ (mbedtls 4.x), the classic mbedTLS APIs are replaced by PSA Crypto.
 * For mbedtls 4.x, we only use the direct CryptoAuthLib APIs.
 */
#if (MBEDTLS_VERSION_NUMBER < 0x04000000)
#define HAVE_MBEDTLS_CLASSIC 1

#if (MBEDTLS_VERSION_NUMBER >= 0x03000000)
/* mbedtls 3.x uses build_info.h instead of config.h */
#include "mbedtls/build_info.h"
#else
/* mbedtls 2.x uses config.h */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#endif /* MBEDTLS_VERSION_NUMBER >= 0x03000000 */

#include "mbedtls/atca_mbedtls_wrap.h"
#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#endif /* MBEDTLS_VERSION_NUMBER < 0x04000000 */

static const char *TAG = "atecc_example";

#if defined(HAVE_MBEDTLS_CLASSIC)
/* globals for mbedtls RNG */
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static int configure_mbedtls_rng(void)
{
    int ret;
    const char * seed = "some random seed string";
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ESP_LOGI(TAG, "Seeding the random number generator...");

    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)seed, strlen(seed));
    if (ret != 0) {
        ESP_LOGI(TAG, " failed  ! mbedtls_ctr_drbg_seed returned %d", ret);
    } else {
        ESP_LOGI(TAG, " ok");
    }
    return ret;
}

static void close_mbedtls_rng(void)
{
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}
#endif /* HAVE_MBEDTLS_CLASSIC */

/* An example hash */
static unsigned char hash[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static const uint8_t public_key_x509_header[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04
};

static void print_public_key(uint8_t *pubkey)
{
    uint8_t buf[128];
    uint8_t * tmp;
    size_t buf_len = sizeof(buf);

    /* Calculate where the raw data will fit into the buffer */
    tmp = buf + sizeof(buf) - ATCA_PUB_KEY_SIZE - sizeof(public_key_x509_header);

    /* Copy the header */
    memcpy(tmp, public_key_x509_header, sizeof(public_key_x509_header));

    /* Copy the key bytes */
    memcpy(tmp + sizeof(public_key_x509_header), pubkey, ATCA_PUB_KEY_SIZE);

    /* Convert to base 64 */
    (void)atcab_base64encode(tmp, ATCA_PUB_KEY_SIZE + sizeof(public_key_x509_header), (char*)buf, &buf_len);

    /* Add a null terminator */
    buf[buf_len] = '\0';

    /* Print out the key */
    ESP_LOGI(TAG, "\r\n-----BEGIN PUBLIC KEY-----\r\n%s\r\n-----END PUBLIC KEY-----", buf);
}

#if defined(HAVE_MBEDTLS_CLASSIC) && (defined(MBEDTLS_ECDSA_SIGN_ALT) || defined(CONFIG_ATCA_MBEDTLS_ECDSA))
static int atca_ecdsa_test(void)
{
    mbedtls_pk_context pkey;
    int ret;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    size_t olen = 0;

    /* ECDSA Sign/Verify */

#ifdef MBEDTLS_ECDSA_SIGN_ALT
    /* Convert to an mbedtls key */
    ESP_LOGI(TAG,  " Using a hardware private key ...");
    ret = atca_mbedtls_pk_init(&pkey, 0);
    if (ret != 0) {
        ESP_LOGI(TAG, " failed !  atca_mbedtls_pk_init returned %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");
#else
    ESP_LOGI(TAG,  " Generating a software private key ...");
    mbedtls_pk_init(&pkey);
    ret = mbedtls_pk_setup(&pkey,
                           mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA));
    if (ret != 0) {
        ESP_LOGI(TAG,  " failed !  mbedtls_pk_setup returned -0x%04x", -ret);
        goto exit;
    }

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                              mbedtls_pk_ec(pkey),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGI(TAG,  " failed !  mbedtls_ecp_gen_key returned -0x%04x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");
#endif

    ESP_LOGI(TAG, " Generating ECDSA Signature...");

#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
    ret = mbedtls_pk_sign(&pkey, MBEDTLS_MD_SHA256, hash, 0, buf, &olen, mbedtls_ctr_drbg_random, &ctr_drbg);
#else
    ret = mbedtls_pk_sign(&pkey, MBEDTLS_MD_SHA256, hash, 0, buf, MBEDTLS_MPI_MAX_SIZE, &olen,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
#endif
    if (ret != 0) {
        ESP_LOGI(TAG, " failed ! mbedtls_pk_sign returned -0x%04x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");

    ESP_LOGI(TAG, " Verifying ECDSA Signature...");
    ret = mbedtls_pk_verify(&pkey, MBEDTLS_MD_SHA256, hash, 0,
                            buf, olen);
    if (ret != 0) {
        ESP_LOGI(TAG, " failed ! mbedtls_pk_verify returned -0x%04x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");

exit:
    fflush(stdout);
    return ret;
}
#endif /* HAVE_MBEDTLS_CLASSIC && (MBEDTLS_ECDSA_SIGN_ALT || CONFIG_ATCA_MBEDTLS_ECDSA) */

static void ecdsa_example_task(void *pvParameter)
{
    int ret = 0;
    bool lock;
    uint8_t buf[ATCA_ECC_CONFIG_SIZE];
    uint8_t pubkey[ATCA_PUB_KEY_SIZE];

    ESP_LOGI(TAG, "Starting ECDSA example task");

#if defined(HAVE_MBEDTLS_CLASSIC)
    /* Initialize the mbedtls library */
    ret = configure_mbedtls_rng();
#endif
#ifdef CONFIG_ATECC608A_TNG
    ESP_LOGI(TAG, "  . Initialize the ATECC interface for Trust & GO ...");
    cfg_ateccx08a_i2c_default.atcai2c.address = 0x6A;
#elif CONFIG_ATECC608A_TFLEX /* CONFIG_ATECC608A_TNGO */
    ESP_LOGI(TAG, "  . Initialize the ATECC interface for TrustFlex ...");
    cfg_ateccx08a_i2c_default.atcai2c.address = 0x6C;
#elif CONFIG_ATECC608A_TCUSTOM /* CONFIG_ATECC608A_TFLEX */
    ESP_LOGI(TAG, "  . Initialize the ATECC interface for TrustCustom ...");
    /* Default slave address is same as that of TCUSTOM ATECC608A chips */
#endif /* CONFIG_ATECC608A_TCUSTOM */
    ret = atcab_init(&cfg_ateccx08a_i2c_default);
    if (ret != 0) {
        ESP_LOGI(TAG, " failed ! atcab_init returned %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");

    lock = 0;
    ESP_LOGI(TAG, " Check the data zone lock status...");
    ret = atcab_is_locked(LOCK_ZONE_DATA, &lock);
    if (ret != 0) {
        ESP_LOGI(TAG, " failed\n  ! atcab_is_locked returned %02x", ret);
        goto exit;
    }

    if (lock) {
        ESP_LOGI(TAG, " ok: locked");
    } else {
        ESP_LOGE(TAG, "unlocked, please lock(configure) the ATECC608A chip with help of esp_cryptoauth_utility and try again");
        goto exit;
    }

    ESP_LOGI(TAG, " Get the device info (type)...");
    ret = atcab_info(buf);
    if (ret != 0) {
        ESP_LOGI(TAG, " failed\n  ! atcab_info returned %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok: %02x %02x", buf[2], buf[3]);

    ESP_LOGI(TAG, " Get the public key...");
    ret = atcab_get_pubkey(0, pubkey);
    if (ret != 0) {
        ESP_LOGI(TAG, " failed\n  ! atcab_get_pubkey returned %02x", ret);
        goto exit;
    }
    ESP_LOGI(TAG, " ok");
    print_public_key(pubkey);

    /* Direct CryptoAuthLib ECDSA test - always works on all ESP-IDF versions */
    ESP_LOGI(TAG, "--- Direct CryptoAuthLib ECDSA Test ---");
    {
        uint8_t signature[ATCA_SIG_SIZE];
        bool is_verified = false;

        ESP_LOGI(TAG, " Signing hash with slot 0...");
        ret = atcab_sign(0, hash, signature);
        if (ret != ATCA_SUCCESS) {
            ESP_LOGE(TAG, " atcab_sign failed: 0x%02x", ret);
            goto exit;
        }
        ESP_LOGI(TAG, " ok");

        ESP_LOGI(TAG, " Verifying signature...");
        ret = atcab_verify_extern(hash, signature, pubkey, &is_verified);
        if (ret != ATCA_SUCCESS) {
            ESP_LOGE(TAG, " atcab_verify_extern failed: 0x%02x", ret);
            goto exit;
        }

        if (!is_verified) {
            ESP_LOGE(TAG, " Signature verification failed!");
            ret = -1;
            goto exit;
        }
        ESP_LOGI(TAG, " ok - Signature verified!");
    }

#if defined(HAVE_MBEDTLS_CLASSIC)
#if defined(MBEDTLS_ECDSA_SIGN_ALT) || defined(CONFIG_ATCA_MBEDTLS_ECDSA)
    /* Perform a Sign/Verify Test using mbedTLS ALT interface */
    ESP_LOGI(TAG, "--- mbedTLS ECDSA Test ---");
    ret = atca_ecdsa_test();
    if (ret != 0) {
        ESP_LOGE(TAG, " mbedTLS ECDSA sign/verify failed");
        goto exit;
    }
#else
    ESP_LOGI(TAG, "mbedTLS ALT test skipped (not enabled)");
#endif
#else
    ESP_LOGI(TAG, "mbedTLS test skipped (mbedtls 4.x - use direct CryptoAuthLib APIs)");
#endif /* HAVE_MBEDTLS_CLASSIC */

    ESP_LOGI(TAG, "ECDSA example task completed successfully");

exit:
    fflush(stdout);
#if defined(HAVE_MBEDTLS_CLASSIC)
    close_mbedtls_rng();
#endif
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_LOGI(TAG, "ECDSA example app_main start");

    /* Create the ECDSA example task */
    xTaskCreate(&ecdsa_example_task, "ecdsa_example_task", 8192, NULL, 5, NULL);
}
