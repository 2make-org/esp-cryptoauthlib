# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ESP-Cryptoauthlib is an Espressif port of Microchip's CryptoAuthLib for ESP-IDF, enabling hardware cryptography using ATECC608A/B secure element chips. The project provides both an ESP-IDF component and a Python provisioning utility.

**Supported targets:** ESP32, ESP32-C2, ESP32-C3, ESP32-C5, ESP32-C6, ESP32-H2, ESP32-P4, ESP32-S3

## Build Commands

### Building the Example
```bash
cd examples/atecc608_ecdsa
idf.py set-target <chip_name>  # e.g., esp32, esp32s3, esp32c3
idf.py menuconfig              # Configure ATECC608 type, I2C pins
idf.py build
idf.py -p PORT flash monitor
```

### Building for Multiple Targets (CI-style)
```bash
idf-build-apps build --target esp32 --paths examples/atecc608_ecdsa
```

### Building Provisioning Firmware
```bash
cd esp_cryptoauth_utility/firmware
idf.py build
esptool.py --chip esp32 elf2image build/ecu_firmware.elf --output ecu_firmware.bin
```

## Architecture

### Integration Modes

**ESP-IDF mbedtls ATECC Driver (ESP-IDF 6.x+, Recommended)** - Uses `CONFIG_MBEDTLS_HARDWARE_ATECC` in ESP-IDF's mbedtls component. This is the recommended approach for ESP-IDF 6.x+ (mbedTLS 4.x):
```c
#include "atecc/atecc_alt.h"

// Initialize ATECC
atcab_init(&cfg_ateccx08a_i2c_default);

// Set up PK context with hardware key
esp_atecc_pk_conf_t conf = {
    .slot_id = 0,
    .grp_id = MBEDTLS_ECP_DP_SECP256R1,
    .load_pubkey = true,
};
mbedtls_pk_context pk;
esp_atecc_set_pk_context(&pk, &conf);

// Use with mbedTLS APIs (TLS client auth, etc.)
mbedtls_pk_sign(&pk, ...);

// Clean up
esp_atecc_free_pk_context(&pk);
```

**mbedTLS ALT (ESP-IDF 4.x - 5.x)** - Uses `MBEDTLS_ECDSA_SIGN_ALT`/`VERIFY_ALT` macros. Enable via `CONFIG_ATCA_MBEDTLS_ECDSA`. NOT compatible with ESP-IDF 6.x+ (mbedTLS 4.x).

**Direct CryptoAuthLib APIs** - Low-level APIs available on all ESP-IDF versions:
- `atcab_sign()` / `atcab_sign_ext()` - ECDSA signing
- `atcab_verify_extern()` - ECDSA verification with external public key
- `atcab_verify_stored()` - ECDSA verification with stored public key
- `atcab_ecdh()` - ECDH key agreement
- `atcab_genkey()` - Key generation
- `atcab_get_pubkey()` - Read public key from slot

### Key Component Layers

```
port/                           # ESP-IDF port layer
├── atca_cfgs_port.c           # I2C device configuration
├── psa_crypto_driver_atecc.c  # PSA Crypto driver (when enabled)
└── psa_atecc_helpers.c        # PSA helper functions

cryptoauthlib/lib/             # Core CryptoAuthLib
├── calib/                     # High-level API (atcab_sign, atcab_verify, etc.)
├── hal/                       # Hardware abstraction
├── atcacert/                  # Certificate handling
└── mbedtls/                   # mbedTLS integration (legacy mode only)

cryptoauthlib/third_party/hal/esp32/
├── hal_esp32_i2c.c           # ESP32 I2C implementation
└── hal_esp32_timer.c         # Timer implementation
```

### ATECC608 Chip Types

- **Trust & Go (TNG)** - Pre-configured, I2C address 0x6A
- **TrustFlex (TFLEX)** - Pre-configured, I2C address 0x6C
- **TrustCustom (TCUSTOM)** - Requires configuration, I2C address 0xC0

## Python Provisioning Utility

```bash
pip install esp-cryptoauth-utility

# Provision/generate manifest
python secure_cert_mfg.py --port /dev/ttyUSB0 \
    --signer-cert signercert.pem --signer-cert-private-key signerkey.pem \
    --i2c-sda-pin 21 --i2c-scl-pin 22

# Detect chip type
python secure_cert_mfg.py --port /dev/ttyUSB0 --type
```

## Configuration (Kconfig)

Key options under `Component config -> esp-cryptoauthlib`:
- `ATECC608A_TYPE` - Chip type selection (TNG, TrustFlex, TrustCustom)
- `ATCA_MBEDTLS_ECDSA` - Enable mbedTLS ALT integration (ESP-IDF 4.x - 5.x only)
- `ATCA_I2C_SDA_PIN`, `ATCA_I2C_SCL_PIN` - I2C pins (default: 21, 22)
- `ATCA_I2C_ADDRESS` - Device address (auto-set based on chip type)
- `ATCA_I2C_USE_LEGACY_DRIVER` - Force legacy I2C driver for ESP-IDF 5.2+

Key options under `Component config -> mbedTLS -> Hardware Acceleration` (ESP-IDF 6.x+):
- `MBEDTLS_HARDWARE_ATECC` - Enable ATECC608 secure element support
- `MBEDTLS_HARDWARE_ATECC_SIGN` - Enable ATECC ECDSA signing
- `MBEDTLS_HARDWARE_ATECC_VERIFY` - Enable ATECC ECDSA verification

## CI/CD Notes

The project tests against ESP-IDF versions v4.3 through v5.5 and latest/master. Pedantic compiler flags are enforced:
```
-Werror -Werror=deprecated-declarations -Werror=unused-variable
-Werror=unused-but-set-variable -Werror=unused-function -Wstrict-prototypes
```

## I2C Driver Compatibility

- ESP-IDF < 5.2: Uses legacy I2C driver only
- ESP-IDF >= 5.2: Uses new I2C driver by default (can force legacy via Kconfig)
- ESP-IDF >= 5.3: Requires `esp_driver_i2c` component dependency
