#
# Copyright (c) 2024 Infineon Technologies AG
#
# SPDX-License-Identifier: MIT
#

cmake_minimum_required(VERSION 3.20.0)

target_compile_definitions(app PRIVATE CONFIG_OPTIGA_TRUST_M_GPIO_VDD_SUPPORT)
target_compile_definitions(app PRIVATE CONFIG_OPTIGA_TRUST_M_GPIO_RST_SUPPORT)
target_compile_definitions(app PRIVATE OPTIGA_COMMS_SHIELDED_CONNECTION)
target_compile_definitions(app PRIVATE XMC4700_BOARD)

# To enable further debugging, please uncomment the lines below :
#target_compile_definitions(app PRIVATE DEBUG)
target_compile_definitions(app PRIVATE OPTIGA_LIB_ENABLE_LOGGING)
target_compile_definitions(app PRIVATE OPTIGA_LIB_ENABLE_CMD_LOGGING)
target_compile_definitions(app PRIVATE OPTIGA_LIB_ENABLE_UTIL_LOGGING)
target_compile_definitions(app PRIVATE MBEDTLS_USER_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../config/mbedtls_user_config.h")

include_directories(${OPTIGA_PATH}/include)
include_directories(${OPTIGA_PATH}/include/cmd)
include_directories(${OPTIGA_PATH}/include/common)
include_directories(${OPTIGA_PATH}/include/comms)
include_directories(${OPTIGA_PATH}/include/ifx_i2c)
include_directories(${OPTIGA_PATH}/include/pal)
include_directories(${OPTIGA_PATH}/external/mbedtls/include)

set(OPTIGA_SOURCES "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal_gpio.c"
                   "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal_i2c.c"
                   "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal_ifx_i2c_config.c"
                   "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal_logger.c"
                   "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal_os_datastore.c"
                   "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal_os_event.c"
                   "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal_os_lock.c"
                   "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal_os_timer.c"
                   "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal.c"
                   "${OPTIGA_PATH}/extras/pal/${OPTIGA_PAL}/pal_os_memory.c"
                   "${OPTIGA_PATH}/extras/pal/pal_crypt_mbedtls.c"
                   "${OPTIGA_PATH}/src/crypt/optiga_crypt.c"
                   "${OPTIGA_PATH}/src/cmd/optiga_cmd.c"
                   "${OPTIGA_PATH}/src/comms/optiga_comms_ifx_i2c.c"
                   "${OPTIGA_PATH}/src/comms/ifx_i2c/ifx_i2c.c"
                   "${OPTIGA_PATH}/src/comms/ifx_i2c/ifx_i2c_config.c"
                   "${OPTIGA_PATH}/src/comms/ifx_i2c/ifx_i2c_transport_layer.c"
                   "${OPTIGA_PATH}/src/comms/ifx_i2c/ifx_i2c_data_link_layer.c"
                   "${OPTIGA_PATH}/src/common/optiga_lib_common.c"
                   "${OPTIGA_PATH}/src/common/optiga_lib_logger.c"
                   "${OPTIGA_PATH}/src/comms/ifx_i2c/ifx_i2c_physical_layer.c"
                   "${OPTIGA_PATH}/src/comms/ifx_i2c/ifx_i2c_presentation_layer.c"
                   "${OPTIGA_PATH}/src/util/optiga_util.c"
                   "${OPTIGA_PATH}/examples/optiga/example_utilities.c"
                   "${OPTIGA_PATH}/examples/optiga/example_optiga_init_deinit.c"
                   "${OPTIGA_PATH}/examples/optiga/example_optiga_crypt_random.c")

set(MBEDTLS_SOURCES "${OPTIGA_PATH}/external/mbedtls/library/ccm.c"
                    "${OPTIGA_PATH}/external/mbedtls/library/cipher.c"
                    "${OPTIGA_PATH}/external/mbedtls/library/platform_util.c"
                    "${OPTIGA_PATH}/external/mbedtls/library/md.c"
                    "${OPTIGA_PATH}/external/mbedtls/library/cipher_wrap.c"
                    "${OPTIGA_PATH}/external/mbedtls/library/constant_time.c"
                    "${OPTIGA_PATH}/external/mbedtls/library/aes.c"
                    "${OPTIGA_PATH}/external/mbedtls/library/sha256.c")

target_sources(app PRIVATE ${OPTIGA_SOURCES} ${MBEDTLS_SOURCES})
target_include_directories(app PRIVATE "${OPTIGA_PATH}/include/"
                                       "${OPTIGA_PATH}/include/pal"
                                       "${OPTIGA_PATH}/include/cmd"
                                       "${OPTIGA_PATH}/include/common"
                                       "${OPTIGA_PATH}/include/comms"
                                       "${OPTIGA_PATH}/include/ifx_i2c"
                                       "${OPTIGA_PATH}/examples/optiga/include/"
                                       "${OPTIGA_PATH}/external/mbedtls/include/"
                                       "${CMAKE_CURRENT_SOURCE_DIR}/../../include/")

