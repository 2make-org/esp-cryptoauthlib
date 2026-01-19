#
# CMakeLists.txt file for cryptoauthlib
#
# This component provides the CryptoAuthLib library for ATECC608 secure elements.
# It supports mbedTLS ALT integration for hardware-accelerated ECDSA operations.
# For ESP-IDF 6.x+, use the direct CryptoAuthLib APIs (atcab_sign, atcab_verify_extern, etc.).
#
cmake_minimum_required(VERSION 3.5)

set(CRYPTOAUTHLIB_DIR "cryptoauthlib/lib")

# Base source directories
set(COMPONENT_SRCDIRS       "${CRYPTOAUTHLIB_DIR}/atcacert"
                            "${CRYPTOAUTHLIB_DIR}/calib"
                            "${CRYPTOAUTHLIB_DIR}/crypto"
                            "${CRYPTOAUTHLIB_DIR}/crypto/hashes"
                            "${CRYPTOAUTHLIB_DIR}/host"
                            "${CRYPTOAUTHLIB_DIR}"
                            "${CRYPTOAUTHLIB_DIR}/../app/tng"
                            "port"
                            )

# Only include mbedtls wrapper files when ATCA_MBEDTLS_ECDSA is enabled
# These files use mbedTLS ALT mechanism which is not compatible with mbedtls 4.x (ESP-IDF 6.x+)
# For ESP-IDF 6.x+, use the ATECC driver in ESP-IDF's mbedtls component instead
if(CONFIG_ATCA_MBEDTLS_ECDSA)
    if("${IDF_VERSION_MAJOR}" VERSION_LESS "6")
        list(APPEND COMPONENT_SRCDIRS "${CRYPTOAUTHLIB_DIR}/mbedtls")
    else()
        message(WARNING "ATCA_MBEDTLS_ECDSA is enabled but not supported on ESP-IDF 6.x+. "
                       "Use CONFIG_MBEDTLS_HARDWARE_ATECC in ESP-IDF's mbedtls component instead.")
    endif()
endif()

# Additional source files (HAL)
set(COMPONENT_SRCS          "${COMPONENT_DIR}/cryptoauthlib/lib/hal/atca_hal.c"
                            "${COMPONENT_DIR}/cryptoauthlib/lib/hal/hal_freertos.c"
                            "${COMPONENT_DIR}/cryptoauthlib/third_party/hal/esp32/hal_esp32_i2c.c"
                            "${COMPONENT_DIR}/cryptoauthlib/third_party/hal/esp32/hal_esp32_timer.c"
                            )

# Add mbedtls patch file only when mbedtls integration is enabled (ESP-IDF 5.x only)
if(CONFIG_ATCA_MBEDTLS_ECDSA AND "${IDF_VERSION_MAJOR}" VERSION_LESS "6")
    list(APPEND COMPONENT_SRCS "${COMPONENT_DIR}/cryptoauthlib/third_party/atca_mbedtls_patch.c")
endif()

# Include directories
set(COMPONENT_INCLUDEDIRS   "${CRYPTOAUTHLIB_DIR}/"
                            "${CRYPTOAUTHLIB_DIR}/hal"
                            "${CRYPTOAUTHLIB_DIR}/../app/tng"
                            "${COMPONENT_DIR}/cryptoauthlib/third_party"
                            "${COMPONENT_DIR}/cryptoauthlib/third_party/hal/esp32/"
                            "port"
                            )

set(COMPONENT_PRIV_INCLUDEDIRS "port/include"
                            "${COMPONENT_DIR}/cryptoauthlib/third_party/"
)

# Required components
set(COMPONENT_REQUIRES      "mbedtls" "freertos" "driver")

# Don't include the default interface configurations from cryptoauthlib
set(COMPONENT_EXCLUDE_SRCS "${CRYPTOAUTHLIB_DIR}/atca_cfgs.c")

# Platform definition
set(COMPONENT_CFLAGS "ESP32")

# Determine I2C driver dependency based on ESP-IDF version
# esp_driver_i2c is available from ESP-IDF 5.3 onwards
if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_GREATER_EQUAL "5.3")
    set(I2C_DRIVER_DEPENDENCY "esp_driver_i2c")
else()
    set(I2C_DRIVER_DEPENDENCY "")
endif()

idf_component_register(     SRC_DIRS        "${COMPONENT_SRCDIRS}"
                            INCLUDE_DIRS    "${COMPONENT_INCLUDEDIRS}"
                            PRIV_INCLUDE_DIRS "${COMPONENT_PRIV_INCLUDEDIRS}"
                            REQUIRES        "${COMPONENT_REQUIRES}"
                            PRIV_REQUIRES   "${I2C_DRIVER_DEPENDENCY}"
                            EXCLUDE_SRCS    "${COMPONENT_EXCLUDE_SRCS}"
                            )

# Add additional source files
target_sources(${COMPONENT_LIB} PRIVATE ${COMPONENT_SRCS})
target_compile_definitions(${COMPONENT_LIB} PRIVATE ${COMPONENT_CFLAGS})

# Compiler warning suppressions
set(COMPONENT_COMPILE_OPTIONS -Wno-pointer-sign -Wno-maybe-uninitialized -Wno-nonnull)

if (CONFIG_COMPILER_OPTIMIZATION_SIZE OR CONFIG_COMPILER_OPTIMIZATION_PERF)
    list(APPEND COMPONENT_COMPILE_OPTIONS -Wno-stringop-overflow)
endif()

target_compile_options(${COMPONENT_LIB} PRIVATE ${COMPONENT_COMPILE_OPTIONS})

# Suppress -Wdiscarded-qualifiers for tng_atcacert_client.c
set_source_files_properties(
    "${CRYPTOAUTHLIB_DIR}/../app/tng/tng_atcacert_client.c"
    PROPERTIES COMPILE_FLAGS "-Wno-discarded-qualifiers"
)
