/*
 * Copyright (c) 2024 Infineon Technologies AG
 *
 * SPDX-License-Identifier: MIT
 *
 * This file provides the example for using OPTIGA Trust M for:
 *  1) Platform Binding and Shielded Connection
 *  2) Local "data-at-rest" protection for arbitrary data and certificates
 */
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include "optiga_example.h"
#include "pal.h"
#include "pal_os_datastore.h"
#include "optiga_crypt.h"
#include "optiga_util.h"
#include "certificate.h"

/*
 * If the OPTIGA Trust M has a pre-configured Platform Binding Secret it needs to be set here:
 */
#define OPTIGA_FIXED_PBS

#ifdef OPTIGA_FIXED_PBS
uint8_t optiga_platform_binding_shared_secret_u[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};
#endif // OPTIGA_FIXED_PBS

/* size of stack area used by each thread */
#define STACKSIZE (4096)

/* scheduling priority used by each thread */
#define PRIORITY 7

/*
 * Get button configuration from the devicetree sw1 alias. This is mandatory.
 * Button is used to trigger initial platform binding with OPTIGA and write custom data.
 */
#define SW1_NODE DT_ALIAS(sw1)
#if !DT_NODE_HAS_STATUS(SW1_NODE, okay)
#error "Unsupported board: sw1 devicetree alias is not defined"
#endif

static const struct gpio_dt_spec button = GPIO_DT_SPEC_GET_OR(SW1_NODE, gpios, {0});
static struct gpio_callback button_cb_data;

/*
 * External functions which are reused in this example
 */
extern void example_optiga_deinit(void);

/*
 * Local variable definitions
 */
static volatile optiga_lib_status_t optiga_lib_status;
static optiga_crypt_t *me_crypt_instance = NULL;
static optiga_util_t *me_util_instance = NULL;
static bool button_pressed_flag = false;

/*
 * Buffer for reading the stored secret data
 * Format: [ SSID_length (1 byte) | SSID (length byte) | Password_length (1 byte) | Password (length byte) ]
 */
#define SECRET_BUFFER_SIZE (sizeof(optiga_trust_m_ca_300_certificate) + 1)
uint8_t secret_buffer[SECRET_BUFFER_SIZE];

/*
 * Definitions for memory layout on OPTIGA
 */
const uint16_t optiga_data_oid = 0xF1D1;
const uint16_t optiga_cert_oid = 0xE0E8;
const uint16_t optiga_data_offset = 0x00;

/*
 * Callback when OPTIGA library function finishes asynchronously.
 */
static void optiga_crypt_callback(void *context, optiga_lib_status_t return_status)
{
    (void) context;
    optiga_lib_status = return_status;
}

/*
 * Takes the raw data, as read from the OPTIGA, and decodes it for application-specific usage.
 * Example encoding: [ SSID_length (1 byte) | SSID (length byte) | Password_length (1 byte) | Password (length byte) ]
 *
 */
static void print_secret_data(uint8_t *secret_buffer, size_t input_buffer_length)
{
    uint8_t offset = 0;
    char ssid[20] = "";
    char password[20] = "";

    uint8_t length = secret_buffer[offset++];

    if (length + 1 > sizeof(ssid) || length > input_buffer_length)
    {
        printk("Parsing of secret data failed (SSID)\n");
        return;
    }
    memcpy(ssid, &secret_buffer[offset], length);

    offset += length;
    length = secret_buffer[offset++];

    if (length + 1 > sizeof(password) || length + offset > input_buffer_length)
    {
        printk("Parsing of secret data failed (Password)\n");
        return;
    }
    memcpy(password, &secret_buffer[offset], length);

    printk("[optiga example]  : SSID: %s\n", ssid);
    printk("[optiga example]  : Password: %s\n", password);
}

static void print_certificate_data(uint8_t *certificate_buffer, size_t certificate_length)
{
    for (size_t i = 0; i < certificate_length; ++i)
    {
        printk("%02x", certificate_buffer[i]);

        if ((i + 1) % 32 == 0)
        {
            printk("\n");
            k_sleep(K_MSEC(10));
        }
    }
    printk("\n");
}

static optiga_lib_status_t pair_host_and_optiga()
{
    optiga_lib_status_t return_status = !OPTIGA_LIB_SUCCESS;
    pal_status_t pal_return_status;
    uint8_t platform_binding_secret_metadata[44];
    size_t pbs_length = 64;
    uint8_t *pbs_buffer = secret_buffer;

    do
    {
        if (me_util_instance)
        {
            /**
             * Destroy old instance
             */
            optiga_util_destroy(me_util_instance);
        }

        if (me_crypt_instance)
        {
            /**
             * Destroy old instance
             */
            optiga_crypt_destroy(me_crypt_instance);
        }

        /**
         * 1. Create OPTIGA Util and Crypt Instances
         */
        me_util_instance = optiga_util_create(0, optiga_crypt_callback, NULL);
        if (me_util_instance == NULL)
        {
            printk("OPTIGA-Lib not initialized, reset device and try again.\n");
            break;
        }

        me_crypt_instance = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == me_crypt_instance)
        {
            break;
        }
        /**
         * 2. Initialize the protection level and protocol version for the instances
         */
        OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util_instance, OPTIGA_COMMS_NO_PROTECTION);
        OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util_instance, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);

        /**
         * 3. Read Platform Binding Shared secret (0xE140) data object metadata from OPTIGA
         *    using optiga_util_read_metadata.
         */
        uint16_t bytes_to_read = sizeof(platform_binding_secret_metadata);
        optiga_lib_status = OPTIGA_LIB_BUSY;

        return_status =
            optiga_util_read_metadata(me_util_instance, 0xE140, platform_binding_secret_metadata, &bytes_to_read);

        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        /**
         * 4. Validate LcsO in the metadata.
         *    Skip the rest of the procedure if LcsO is greater than or equal to operational state(0x07)
         */
        if (platform_binding_secret_metadata[4] >= 0x07)
        {
            /*
             * The LcsO is already greater than or equal to operational state, this is only allowed when a fixed PBS is
             * configured. Write the PBS to the datastore, it will be used by the library to establish the shielded
             * connection.
             */
#ifdef OPTIGA_FIXED_PBS
            pal_return_status =
                pal_os_datastore_write(OPTIGA_PLATFORM_BINDING_SHARED_SECRET_ID, optiga_platform_binding_shared_secret_u,
                                       sizeof(optiga_platform_binding_shared_secret_u));
            return_status = pal_return_status;
#endif
            break;
        }

#ifdef OPTIGA_FIXED_PBS
        /**
         * 5a. Use statically configured PBS value.
         */
        pbs_buffer = optiga_platform_binding_shared_secret_u;
        pbs_length = sizeof(optiga_platform_binding_shared_secret_u);

#else
        /**
         * 5b. Generate Random using optiga_crypt_random
         *       - Specify the Random type as TRNG
         *    a. The maximum supported size of secret is 64 bytes.
         *       The minimum recommended is 32 bytes.
         *    b. If the host platform doesn't support random generation,
         *       use OPTIGA to generate the maximum size chosen.
         *       else choose the appropriate length of random to be generated by OPTIGA
         *
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_random(me_crypt_instance, OPTIGA_RNG_TYPE_TRNG, pbs_buffer, pbs_length);
        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);
#endif
        /**
         * 6. Generate random on Host
         *    If the host platform doesn't support, skip this step
         */

        /**
         * 7. Write random(secret) to OPTIGA platform Binding shared secret data object (0xE140)
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util_instance, OPTIGA_COMMS_NO_PROTECTION);
        return_status =
            optiga_util_write_data(me_util_instance, 0xE140, OPTIGA_UTIL_ERASE_AND_WRITE, 0, pbs_buffer, pbs_length);
        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        /**
         * 8. Write/store the random(secret) on the Host platform
         *
         */
        pal_return_status = pal_os_datastore_write(OPTIGA_PLATFORM_BINDING_SHARED_SECRET_ID, pbs_buffer, pbs_length);

        if (pal_return_status != PAL_STATUS_SUCCESS)
        {
            // Storing of Pre-shared secret on Host failed.
            optiga_lib_status = pal_return_status;
            break;
        }

        /**
         * 9. Optional: Update metadata of OPTIGA Platform Binding shared secret data object (0xE140) and lifecycle
         * state to seal binding. Not done in demo to prevent unintentional locking of OPTIGA. See
         * example_pair_host_and_optiga_using_pre_shared_secret.c for details
         */

        return_status = OPTIGA_LIB_SUCCESS;

    } while (0);
    return return_status;
}

/*
 * Function to refresh platform binding and write secret data to OPTIGA Trust-M.
 * Do not call this action directly from an ISR (e.g. on button press).
 */
void button_pressed_handler()
{
    const uint8_t default_ssid[] = "TESTSSID";
    const uint8_t default_pwd[] = "TESTPWD";
    const uint8_t timestamp_length = 4;
    size_t offset = 0;
    uint32_t timestamp = k_uptime_get_32();

    optiga_lib_status_t return_status = !OPTIGA_LIB_SUCCESS;
    printk("Button pressed, resetting secret data.\n");

    do
    {
        /*
         * Perform platform binding
         */
        printk("[optiga example]  : Pair host and optiga!\n");
        return_status = pair_host_and_optiga();
        if (return_status != OPTIGA_LIB_SUCCESS)
        {
            printk("Platform binding failed!\n");
            break;
        }

        if (me_util_instance == NULL)
        {
            me_util_instance = optiga_util_create(0, optiga_crypt_callback, NULL);
            if (me_util_instance == NULL)
            {
                printk("OPTIGA-Lib not initialized, reset device and try again.\n");
                break;
            }
        }

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_open_application(me_util_instance, 0);

        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        /*
         * Prepare demo data in buffer
         */
        uint8_t data_length = (uint8_t) sizeof(default_ssid);
        memcpy(&secret_buffer[offset++], &data_length, 1);
        memcpy(&secret_buffer[offset], default_ssid, sizeof(default_ssid));
        offset += data_length;

        /*
         * Adding random timestamp to default password for demo
         */
        data_length = (uint8_t) (sizeof(default_pwd) + timestamp_length);
        memcpy(&secret_buffer[offset++], &data_length, 1);
        memcpy(&secret_buffer[offset], default_pwd, sizeof(default_pwd) - 1);
        offset += sizeof(default_pwd) - 1;

        for (size_t i = 0; i < timestamp_length; ++i)
        {
            /*
             * Get some 'random' digits out of the timestamp
             */
            secret_buffer[offset++] = '0' + (timestamp & 0b111);
            timestamp = timestamp >> 3;
        }

        secret_buffer[offset++] = '\0';
        data_length = offset;

        /*
         * Enable Shielded Connection
         */
        OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util_instance, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
        OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util_instance, OPTIGA_COMMS_FULL_PROTECTION);

        /*
         * Write data to OPTIGA
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_write_data(me_util_instance, optiga_data_oid, OPTIGA_UTIL_ERASE_AND_WRITE,
                                               optiga_data_offset, secret_buffer, data_length);

        if (return_status != PAL_STATUS_SUCCESS)
        {
            printk("Secret data write Failed!\n");
            break;
        }

        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        /*
         * Write certificate to OPTIGA
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status =
            optiga_util_write_data(me_util_instance, optiga_cert_oid, OPTIGA_UTIL_ERASE_AND_WRITE, optiga_data_offset,
                                   optiga_trust_m_ca_300_certificate, sizeof(optiga_trust_m_ca_300_certificate));

        if (return_status != PAL_STATUS_SUCCESS)
        {
            printk("Certificate write Failed! %x\n", return_status);
            break;
        }

        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        printk("[optiga example]  : Secret data written to OPTIGA:\n");
        print_secret_data(secret_buffer, SECRET_BUFFER_SIZE);
    } while (0);
}

/*
 * GPIO ISR callback for user button.
 */
void button_pressed(const struct device *dev, struct gpio_callback *callback, uint32_t pins)
{
    (void) dev;
    (void) callback;
    (void) pins;

    /*
     * Do not call OPTIGA library functions from ISR context directly. Instead use a worker thread or set flag to notify
     * main thread.
     */
    button_pressed_flag = true;
}

/*
 * Configure the button interrupt for user interaction.
 */
static void initialize_user_button(void)
{
    int ret;

    if (!gpio_is_ready_dt(&button))
    {
        printk("Error: button device %s is not ready\n", button.port->name);
        return;
    }

    ret = gpio_pin_configure_dt(&button, GPIO_INPUT);
    if (ret != 0)
    {
        printk("Error %d: failed to configure %s pin %d\n", ret, button.port->name, button.pin);
        return;
    }

    ret = gpio_pin_interrupt_configure_dt(&button, GPIO_INT_EDGE_TO_ACTIVE);
    if (ret != 0)
    {
        printk("Error %d: failed to configure interrupt on %s pin %d\n", ret, button.port->name, button.pin);
        return;
    }

    gpio_init_callback(&button_cb_data, button_pressed, BIT(button.pin));
    gpio_add_callback(button.port, &button_cb_data);
}

/*
 * Read the stored secret data from OPTIGA and print to console.
 */
static pal_status_t read_optiga_secret_data(optiga_util_t *me_util, const uint16_t optiga_oid, uint8_t *p_secret_buffer,
                                            uint16_t buffer_length)
{
    optiga_lib_status_t return_status = !OPTIGA_LIB_SUCCESS;
    uint16_t bytes_to_read = buffer_length - 1;

    if (me_util == NULL)
    {
        return PAL_STATUS_INVALID_INPUT;
    }

    optiga_lib_status = OPTIGA_LIB_BUSY;

    do
    {
        OPTIGA_UTIL_SET_COMMS_PROTOCOL_VERSION(me_util, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
        OPTIGA_UTIL_SET_COMMS_PROTECTION_LEVEL(me_util, OPTIGA_COMMS_FULL_PROTECTION);

        return_status = optiga_util_read_data(me_util, optiga_oid, optiga_data_offset, p_secret_buffer, &bytes_to_read);

        while (optiga_lib_status == OPTIGA_LIB_BUSY)
        {
            k_sleep(K_MSEC(100));
        }

        if (return_status != OPTIGA_LIB_SUCCESS)
        {
            printk("Util_read failed! %d\n", return_status);
            return return_status;
        }

        if (bytes_to_read == 0 || p_secret_buffer[0] == '\0')
        {
            printk("Stored secret data empty!\n");
            return OPTIGA_LIB_SUCCESS;
        }
        p_secret_buffer[bytes_to_read] = '\0';
    } while (0);
    return return_status;
}

/*
 * Main example function to show Shielded Connection and reading of secret data from OPTIGA.
 */
void optiga_example(void)
{
    optiga_lib_status_t return_status;

    printf("Zephyr Optiga Trust M application started \r\n");

    /* Configure the button interrupt for user interaction. */
#ifndef XMC4700_BOARD
    initialize_user_button();
#endif

    do
    {
        return_status = pal_init();
        if (return_status != PAL_STATUS_SUCCESS)
        {
            printk("PAL initialization failed!\r\n");
        }

        /*
         * Create an instance of optiga_util to open the application on OPTIGA.
         */
        me_util_instance = optiga_util_create(0, optiga_crypt_callback, NULL);
        if (NULL == me_util_instance)
        {
            printk("optiga_util_create failed!\r\n");
            break;
        }

        /*
         * Open the application on OPTIGA which is a precondition to perform any other operations
         * using optiga_util_open_application
         */
        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_util_open_application(me_util_instance, 0);

        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        printk("[optiga example]  : Read certificate data from OPTIGA!\r\n");
        return_status =
            read_optiga_secret_data(me_util_instance, optiga_cert_oid, secret_buffer, sizeof(secret_buffer));

        if (return_status != PAL_STATUS_SUCCESS)
        {
            printk("Example read_secret_data failed!\r\n");
            break;
        }

        print_certificate_data(secret_buffer, sizeof(optiga_trust_m_ca_300_certificate));

        printk("[optiga example]  : Read secret data from OPTIGA!\r\n");
        return_status =
            read_optiga_secret_data(me_util_instance, optiga_data_oid, secret_buffer, sizeof(secret_buffer));

        if (return_status != PAL_STATUS_SUCCESS)
        {
            printk("Example read_secret_data failed!\r\n");
            break;
        }

        print_secret_data(secret_buffer, sizeof(secret_buffer));

        /*
         * Create an instance of optiga_crypt to perform any crypto
         * operation on the OPTIGA device.
         */
        me_crypt_instance = optiga_crypt_create(0, optiga_crypt_callback, NULL);
        if (NULL == me_crypt_instance)
        {
            printk("optiga_util_create failed!\r\n");
            break;
        }

        /*
         * Perform any operation with the OPTIGA device; e.g., get
         * a true random number. random_data_buffer should contain the resulting
         * random number. Enable Shielded Connection if data is used in security relevant context.
         */

        printk("\n[optiga example]  : Retrieve random data over protected connection\n");
        OPTIGA_CRYPT_SET_COMMS_PROTOCOL_VERSION(me_crypt_instance, OPTIGA_COMMS_PROTOCOL_VERSION_PRE_SHARED_SECRET);
        OPTIGA_CRYPT_SET_COMMS_PROTECTION_LEVEL(me_crypt_instance, OPTIGA_COMMS_FULL_PROTECTION);

        optiga_lib_status = OPTIGA_LIB_BUSY;
        return_status = optiga_crypt_random(me_crypt_instance, OPTIGA_RNG_TYPE_TRNG, secret_buffer, 32);

        WAIT_AND_CHECK_STATUS(return_status, optiga_lib_status);

        printk("[optiga example]  : Passed\r\n");

    } while (0);

    if (return_status != PAL_STATUS_SUCCESS)
    {
        printk("[optiga example]  : Examples failed! return_status : %d \r\n", return_status);
    }

#ifdef XMC4700_BOARD
    while (true)
    {
        printk("\nwaiting 5 seconds then store data and perform fresh platform binding!\n");
        pal_os_timer_delay_in_milliseconds(5000);

        button_pressed_handler();
    }
#else

    while (true)
    {
        if (button_pressed_flag)
        {
            button_pressed_handler();
            button_pressed_flag = false;
        }
        k_sleep(K_MSEC(100));
    }

#endif

    /*
     * Close the application on OPTIGA after all the operations are executed
     * using optiga_util_close_application. Not reached in this example, but given as best-practice.
     */
    example_optiga_deinit();
}

// NOLINTBEGIN(misc-misplaced-const)
K_THREAD_DEFINE(optiga_example_id, STACKSIZE, optiga_example, NULL, NULL, NULL, PRIORITY, 0, 1);
// NOLINTEND(misc-misplaced-const)
