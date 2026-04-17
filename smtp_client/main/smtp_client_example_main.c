/**
 * SMTP email client
 *
 * Adapted from the `ssl_mail_client` example in mbedtls.
 *
 * Original Copyright (C) 2006-2016, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) Copyright 2015-2020 Espressif Systems (Shanghai) PTE LTD, Apache 2.0 License.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "driver/gpio.h"


#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include <mbedtls/base64.h>
#include <sys/param.h>

#define MAIL_SERVER         "smtp-relay.brevo.com"
#define MAIL_PORT           "587"           /* 465 = implicit TLS (SMTPS) */
#define USER_MAIL         "a363f1001@smtp-brevo.com"
#define SENDER_MAIL         "johannes.dupont@cloud-spot.de"
#define SENDER_PASSWORD     "xsmtpsib-43fad25226f31b03c1e2fd078e21a3a87cd346b92b08d66e1def7ace5fbdf7d3-jFzNAGlaWhT2UpTg"
#define RECIPIENT_MAIL      "shakaibnaqvi401@gmail.com"

/* Set to 0 for port 465 (implicit TLS).
 * Set to 1 for port 587 (STARTTLS) — */
#define SERVER_USES_STARTSSL 1

static const char *TAG = "smtp_example";

#define TASK_STACK_SIZE     (8 * 1024)
#define BUF_SIZE            512

/* enlarged from 128 to 256 to safely handle base64 of long addresses */
#define BASE64_BUF_SIZE     256

#define VALIDATE_MBEDTLS_RETURN(ret, min_valid_ret, max_valid_ret, goto_label)  \
    do {                                                                        \
        if (ret < min_valid_ret || ret > max_valid_ret) {                       \
            ESP_LOGE(TAG, "Unexpected SMTP response code: %d", ret);            \
            goto goto_label;                                                    \
        }                                                                       \
    } while (0)


// extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
// extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");

/* Uncomment if you want to send an image attachment:
extern const uint8_t sample_image_jpg_start[] asm("_binary_sample_image_jpg_start");
extern const uint8_t sample_image_jpg_end[]   asm("_binary_sample_image_jpg_end");
*/

/* --------------------------------------------------------------------------
 * write_and_get_response — plain (non-TLS) socket read/write.
 * Only used during the STARTTLS negotiation phase (port 587 flow).
 * -------------------------------------------------------------------------- */
static int write_and_get_response(mbedtls_net_context *sock_fd, unsigned char *buf, size_t len)
{
    int ret;
    const size_t DATA_SIZE = 128;
    unsigned char data[DATA_SIZE];
    char code[4];
    size_t i, idx = 0;

    if (len) {
        ESP_LOGD(TAG, "%s", buf);
    }

    if (len && (ret = mbedtls_net_send(sock_fd, buf, len)) <= 0) {
        ESP_LOGE(TAG, "mbedtls_net_send failed with error -0x%x", -ret);
        return ret;
    }

    do {
        len = DATA_SIZE - 1;
        ret = mbedtls_net_recv(sock_fd, data, len);

        if (ret <= 0) {
            ESP_LOGE(TAG, "mbedtls_net_recv failed with error -0x%x", -ret);
            ret = -1;
            goto exit;
        }

        data[ret] = '\0';
        printf("\n%s", data);
        len = ret;

        for (i = 0; i < len; i++) {
            if (data[i] != '\n') {
                if (idx < 4) {
                    code[idx++] = data[i];
                }
                continue;
            }

            if (idx == 4 && code[0] >= '0' && code[0] <= '9' && code[3] == ' ') {
                code[3] = '\0';
                ret = atoi(code);
                goto exit;
            }

            idx = 0;
        }
    } while (1);

exit:
    return ret;
}

/* --------------------------------------------------------------------------
 * write_ssl_and_get_response — TLS socket write then read SMTP response code.
 * -------------------------------------------------------------------------- */
static int write_ssl_and_get_response(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len)
{
    int ret;
    const size_t DATA_SIZE = 128;
    unsigned char data[DATA_SIZE];
    char code[4];
    size_t i, idx = 0;

    if (len) {
        ESP_LOGD(TAG, "%s", buf);
    }

    while (len && (ret = mbedtls_ssl_write(ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_write failed with error -0x%x", -ret);
            goto exit;
        }
    }

    do {
        len = DATA_SIZE - 1;
        ret = mbedtls_ssl_read(ssl, data, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret <= 0) {
            ESP_LOGE(TAG, "mbedtls_ssl_read failed with error -0x%x", -ret);
            goto exit;
        }

        data[ret] = '\0';   /* FIX: terminate at actual length */
        ESP_LOGD(TAG, "%s", data);
        len = ret;

        for (i = 0; i < len; i++) {
            if (data[i] != '\n') {
                if (idx < 4) {
                    code[idx++] = data[i];
                }
                continue;
            }

            if (idx == 4 && code[0] >= '0' && code[0] <= '9' && code[3] == ' ') {
                code[3] = '\0';
                ret = atoi(code);
                goto exit;
            }

            idx = 0;
        }
    } while (1);

exit:
    return ret;
}

/* --------------------------------------------------------------------------
 * write_ssl_data — TLS socket write with no response reading.
 * -------------------------------------------------------------------------- */
static int write_ssl_data(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len)
{
    int ret = 0;

    if (len) {
        ESP_LOGD(TAG, "%s", buf);
    }

    while (len && (ret = mbedtls_ssl_write(ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_write failed with error -0x%x", -ret);
            return ret;
        }
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * perform_tls_handshake
 * -------------------------------------------------------------------------- */
static int perform_tls_handshake(mbedtls_ssl_context *ssl)
{
    int ret = -1;
    uint32_t flags;
    char *buf = NULL;

    buf = (char *) calloc(1, BUF_SIZE);
    if (buf == NULL) {
        ESP_LOGE(TAG, "calloc failed for size %d", BUF_SIZE);
        goto exit;
    }

    ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

    fflush(stdout);
    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            goto exit;
        }
    }

    ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(ssl)) != 0) {
        ESP_LOGW(TAG, "Failed to verify peer certificate!");
        mbedtls_x509_crt_verify_info(buf, BUF_SIZE, "  ! ", flags);
        ESP_LOGW(TAG, "verification info: %s", buf);
        /* For production: treat cert failure as fatal — uncomment below:
         * ret = -1; goto exit; */
    } else {
        ESP_LOGI(TAG, "Certificate verified.");
    }

    ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(ssl));
    ret = 0;

exit:
    if (buf) {
        free(buf);
    }
    return ret;
}

/* --------------------------------------------------------------------------
 * smtp_client_task
 * -------------------------------------------------------------------------- */
static void smtp_client_task(void *pvParameters)
{
    char *buf = NULL;
    /* FIX #6 — enlarged buffer to 256 bytes */
    unsigned char base64_buffer[BASE64_BUF_SIZE];
    int ret, len;
    size_t base64_len;

    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context      ssl;
    mbedtls_x509_crt         cacert;
    mbedtls_ssl_config       conf;
    mbedtls_net_context      server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);

    /* ---- Seed RNG ---- */
    ESP_LOGI(TAG, "Seeding the random number generator...");
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL, 0)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        goto exit;
    }

    // ESP_LOGI(TAG, "Loading the CA root certificate...");
    // ret = mbedtls_x509_crt_parse(&cacert,
    //                              server_root_cert_pem_start,
    //                              server_root_cert_pem_end - server_root_cert_pem_start);
    // if (ret < 0) {
    //     ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x", -ret);
    //     goto exit;
    // }

    /* ---- TLS configuration ---- */
    ESP_LOGI(TAG, "Setting hostname for TLS session...");
    if ((ret = mbedtls_ssl_set_hostname(&ssl, MAIL_SERVER)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x", -ret);
        goto exit;
    }

    /* ---- Connect ---- */
    mbedtls_net_init(&server_fd);
    ESP_LOGI(TAG, "Connecting to %s:%s...", MAIL_SERVER, MAIL_PORT);

    if ((ret = mbedtls_net_connect(&server_fd, MAIL_SERVER,
                                   MAIL_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        ESP_LOGE(TAG, "mbedtls_net_connect returned -0x%x", -ret);
        goto exit;
    }
    ESP_LOGI(TAG, "Connected.");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* ---- Allocate working buffer ---- */
    buf = (char *) calloc(1, BUF_SIZE);
    if (buf == NULL) {
        ESP_LOGE(TAG, "calloc failed for size %d", BUF_SIZE);
        goto exit;
    }

/* --------------------------------------------------------------------------
 *
 * SERVER_USES_STARTSSL 0  →  port 465, TLS handshake FIRST, then EHLO over TLS.
 * SERVER_USES_STARTSSL 1  →  port 587, plain EHLO → STARTTLS command →
 *                             TLS handshake → EHLO again over TLS.
 * -------------------------------------------------------------------------- */
#if SERVER_USES_STARTSSL

    /* --- Port 587 / STARTTLS flow --- */
    /* 1. Plain TCP: read greeting */
    ret = write_and_get_response(&server_fd, (unsigned char *) buf, 0);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    /* 2. Plain TCP: EHLO */
    ESP_LOGI(TAG, "Writing EHLO to server...");
    len = snprintf(buf, BUF_SIZE, "EHLO %s\r\n", "ESP32");
    ret = write_and_get_response(&server_fd, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    /* 3. Plain TCP: request STARTTLS upgrade */
    ESP_LOGI(TAG, "Writing STARTTLS to server...");
    len = snprintf(buf, BUF_SIZE, "STARTTLS\r\n");
    ret = write_and_get_response(&server_fd, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    /* 4. Perform TLS handshake now that server agreed */
    ret = perform_tls_handshake(&ssl);
    if (ret != 0) {
        goto exit;
    }

    /* 5. Re-send EHLO over the now-encrypted channel */
    ESP_LOGI(TAG, "Writing EHLO (post-TLS) to server...");
    len = snprintf(buf, BUF_SIZE, "EHLO %s\r\n", "ESP32");
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

#else /* SERVER_USES_STARTSSL == 0 — port 465, implicit TLS */

    /* 1. TLS handshake immediately */
    ret = perform_tls_handshake(&ssl);
    if (ret != 0) {
        goto exit;
    }

    /* 2. Read greeting over TLS */
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, 0);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    /* 3. EHLO over TLS */
    ESP_LOGI(TAG, "Writing EHLO to server...");
    len = snprintf(buf, BUF_SIZE, "EHLO %s\r\n", "ESP32");
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

#endif /* SERVER_USES_STARTSSL */

    /* ---- Authentication ---- */
    ESP_LOGI(TAG, "Authentication...");

    ESP_LOGI(TAG, "Write AUTH LOGIN");
    len = snprintf(buf, BUF_SIZE, "AUTH LOGIN\r\n");
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 300, 399, exit);

    ESP_LOGI(TAG, "Write USER NAME");
    ret = mbedtls_base64_encode(base64_buffer, sizeof(base64_buffer),
                                &base64_len,
                                (const unsigned char *) USER_MAIL, strlen(USER_MAIL));
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_base64_encode failed for username: %d", ret);
        goto exit;
    }
    base64_buffer[base64_len] = '\0';
    len = snprintf(buf, BUF_SIZE, "%s\r\n", base64_buffer);
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 300, 399, exit);

    ESP_LOGI(TAG, "Write PASSWORD");
    ret = mbedtls_base64_encode(base64_buffer, sizeof(base64_buffer),
                                &base64_len,
                                (const unsigned char *) SENDER_PASSWORD, strlen(SENDER_PASSWORD));
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_base64_encode failed for password: %d", ret);
        goto exit;
    }
    base64_buffer[base64_len] = '\0';
    len = snprintf(buf, BUF_SIZE, "%s\r\n", base64_buffer);
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    /* ---- Envelope ---- */
    ESP_LOGI(TAG, "Write MAIL FROM");
    len = snprintf(buf, BUF_SIZE, "MAIL FROM:<%s>\r\n", SENDER_MAIL);
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    ESP_LOGI(TAG, "Write RCPT TO");
    len = snprintf(buf, BUF_SIZE, "RCPT TO:<%s>\r\n", RECIPIENT_MAIL);
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    ESP_LOGI(TAG, "Write DATA");
    len = snprintf(buf, BUF_SIZE, "DATA\r\n");
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 300, 399, exit);

    /* ---- Headers ---- */
    /* FIX #4 — All MIME/header lines use \r\n throughout */
    ESP_LOGI(TAG, "Write Headers");
    len = snprintf(buf, BUF_SIZE,
                   "From: ESP32 SMTP Client <%s>\r\n"
                   "To: %s\r\n"
                   "Subject: mbedTLS Test Mail\r\n"
                   "MIME-Version: 1.0\r\n"
                   "Content-Type: multipart/mixed; boundary=\"XYZabcd1234\"\r\n"
                   "\r\n",
                   SENDER_MAIL, RECIPIENT_MAIL);
    ret = write_ssl_data(&ssl, (unsigned char *) buf, len);
    if (ret != 0) { goto exit; }   /* FIX #5 */

    /* ---- Text part ---- */
    len = snprintf(buf, BUF_SIZE,
                   "--XYZabcd1234\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n"
                   "\r\n"
                   "This is a simple test mail from the ESP32 SMTP client example.\r\n"
                   "\r\n"
                   "Enjoy!\r\n");
    ret = write_ssl_data(&ssl, (unsigned char *) buf, len);
    if (ret != 0) { goto exit; }   /* FIX #5 */

    /* ---- Attachment header ---- */
    len = snprintf(buf, BUF_SIZE,
                   "--XYZabcd1234\r\n"
                   "Content-Type: image/jpeg; name=\"test_image.jpg\"\r\n"
                   "Content-Transfer-Encoding: base64\r\n"
                   "Content-Disposition: attachment; filename=\"test_image.jpg\"\r\n"
                   "\r\n");
    ret = write_ssl_data(&ssl, (unsigned char *) buf, len);
    if (ret != 0) { goto exit; }   /* FIX #5 */

    /* ---- Image attachment body (uncomment when you embed the file) ----
    {
        const uint8_t *offset = sample_image_jpg_start;
        while (offset < sample_image_jpg_end) {
            int chunk = MIN(((sizeof(base64_buffer) - 1) / 4) * 3,
                            (int)(sample_image_jpg_end - offset));
            ret = mbedtls_base64_encode(base64_buffer, sizeof(base64_buffer),
                                        &base64_len, offset, chunk);
            if (ret != 0) {
                ESP_LOGE(TAG, "mbedtls_base64_encode error: %d", ret);
                goto exit;
            }
            offset += chunk;
            base64_buffer[base64_len] = '\0';
            len = snprintf(buf, BUF_SIZE, "%s\r\n", base64_buffer);
            ret = write_ssl_data(&ssl, (unsigned char *) buf, len);
            if (ret != 0) { goto exit; }
        }
    }
    ---- */

    /* ---- Closing boundary ---- */
    len = snprintf(buf, BUF_SIZE, "--XYZabcd1234--\r\n");
    ret = write_ssl_data(&ssl, (unsigned char *) buf, len);
    if (ret != 0) { goto exit; }   /* FIX #5 */

    /* ---- End of DATA ---- */
    len = snprintf(buf, BUF_SIZE, "\r\n.\r\n");
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    /* ---- Quit ---- */
    len = snprintf(buf, BUF_SIZE, "QUIT\r\n");
    ret = write_ssl_and_get_response(&ssl, (unsigned char *) buf, len);
    VALIDATE_MBEDTLS_RETURN(ret, 200, 299, exit);

    mbedtls_ssl_close_notify(&ssl);
    ESP_LOGI(TAG, "Email sent successfully!");
    ret = 0;

exit:
    mbedtls_ssl_session_reset(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (ret != 0 && buf != NULL) {
        mbedtls_strerror(ret, buf, BUF_SIZE);
        ESP_LOGE(TAG, "Last error: -0x%x - %s", -ret, buf);
    }

    putchar('\n');
    if (buf) {
        free(buf);
    }
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /**
     * Configures Wi-Fi or Ethernet as selected in menuconfig.
     * See examples/protocols/README.md for details.
     */
    gpio_config_t io_conf = {
        .mode = GPIO_MODE_OUTPUT,
        .pin_bit_mask = (1ULL << GPIO_NUM_4),
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .pull_up_en = GPIO_PULLUP_DISABLE
    };
    gpio_config(&io_conf);

    gpio_set_level(GPIO_NUM_4, 1);
    vTaskDelay(2000 / portTICK_PERIOD_MS);
    gpio_set_level(GPIO_NUM_4, 0);

    ESP_ERROR_CHECK(example_connect());
    xTaskCreate(&smtp_client_task, "smtp_client_task", TASK_STACK_SIZE, NULL, 5, NULL);
}