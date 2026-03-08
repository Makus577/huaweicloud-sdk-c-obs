/*********************************************************************************
* Copyright 2024 Huawei Technologies Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* You may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software distributed
* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
* CONDITIONS OF ANY KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations under the License.
**********************************************************************************
*/

/**
 * @file test_types.h
 * @brief Type definitions for unit testing
 *
 * This file contains minimal type definitions needed for unit testing
 * without requiring the full SDK headers.
 */

#ifndef TEST_TYPES_H
#define TEST_TYPES_H

#include <curl/curl.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Status codes
 * ============================================================================ */

typedef enum {
    OBS_STATUS_OK = 0,
    OBS_STATUS_InvalidParameter,
    OBS_STATUS_GM_EncCertNotFound,
    OBS_STATUS_GM_TongsuoNotSupported,
    OBS_STATUS_SSL_CertNotFound,
    OBS_STATUS_SSL_KeyNotFound
} obs_status;

/* ============================================================================
 * Configuration switches
 * ============================================================================ */

typedef enum {
    OBS_CLIENT_AUTH_CLOSE = 0,
    OBS_CLIENT_AUTH_OPEN = 1
} obs_client_auth_switch;

typedef enum {
    OBS_GM_MODE_CLOSE = 0,
    OBS_GM_MODE_OPEN = 1
} obs_gm_mode_switch;

/* ============================================================================
 * Request options
 * ============================================================================ */

typedef struct {
    char* server_cert_path;
    char* client_cert_path;
    char* client_key_path;
    char* client_enc_cert_path;
    char* client_enc_key_path;
    char* ssl_cipher_list;
    int ssl_version;
    int ssl_verifyhost;
    int keep_alive;
    int keep_idle;
    int keep_intvl;
    char* proxy_host;
    char* proxy_auth;
    int forbid_reuse_tcp;
    int curl_max_connects;
    int bbr_switch;
    int http2_switch;
    int speed_limit;
    int speed_time;
    int connect_time;
    int max_connected_time;
    int buffer_size;
    int curl_log_verbose;

    obs_client_auth_switch client_auth_switch;
    obs_gm_mode_switch gm_mode_switch;

    int (*password_callback)(void *context, char *password_buffer, size_t buffer_size);
    void *password_callback_context;
} obs_http_request_option;

/* ============================================================================
 * Bucket context
 * ============================================================================ */

typedef struct {
    void* certificate_info;
} obs_bucket_context;

/* ============================================================================
 * HTTP request
 * ============================================================================ */

typedef struct {
    CURL* curl;
    struct curl_slist* headers;
    char* uri;
} http_request;

/* ============================================================================
 * Request parameters
 * ============================================================================ */

typedef struct {
    obs_http_request_option request_option;
    obs_bucket_context bucketContext;
    int isCheckCA;
} request_params;

/* ============================================================================
 * Computed values
 * ============================================================================ */

typedef struct {
    char computed[256];
} request_computed_values;

/* ============================================================================
 * Callback types
 * ============================================================================ */

/* pem_password_cb is already defined in OpenSSL headers, so we don't redefine it here */

#ifdef __cplusplus
}
#endif

#endif /* TEST_TYPES_H */
