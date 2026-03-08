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
 * @file test_mocks.c
 * @brief Implementation of mock framework
 */

#include "test_mocks.h"
#include <string.h>

/* Global mock state */
mock_state_t g_mock_state = { 0 };

/* ============================================================================
 * Mock initialization and cleanup
 * ============================================================================ */

void mock_init(void) {
    memset(&g_mock_state, 0, sizeof(g_mock_state));
    g_mock_state.initialized = 1;

    /* Set default successful results for all options */
    for (int i = 0; i < 256; i++) {
        g_mock_state.curl_setopt_results[i] = CURLE_OK;
    }
    g_mock_state.curl_init_result = (CURL*)0x12345678;
    g_mock_state.curl_perform_result = CURLE_OK;
}

void mock_cleanup(void) {
    memset(&g_mock_state, 0, sizeof(g_mock_state));
}

void mock_reset(void) {
    mock_cleanup();
    mock_init();
}

/* ============================================================================
 * Curl mock implementations
 * ============================================================================ */

CURLcode mock_curl_easy_setopt(CURL *curl, CURLoption option, ...) {
    /* Check if this call should fail */
    int fail_idx = g_mock_state.curl_setopt_fail_index;
    if (fail_idx == (int)g_mock_state.curl_setopt_call_count) {
        g_mock_state.curl_setopt_call_count++;
        return g_mock_state.curl_setopt_results[option];
    }

    g_mock_state.curl_setopt_call_count++;

    /* Return the configured result for this option */
    if (option < 256) {
        return g_mock_state.curl_setopt_results[option];
    }

    return CURLE_OK;
}

CURL* mock_curl_easy_init(void) {
    g_mock_state.curl_init_call_count++;
    return g_mock_state.curl_init_result;
}

void mock_curl_easy_cleanup(CURL *curl) {
    g_mock_state.curl_cleanup_call_count++;
    (void)curl;
}

CURLcode mock_curl_easy_perform(CURL *curl) {
    g_mock_state.curl_perform_call_count++;
    (void)curl;
    return g_mock_state.curl_perform_result;
}

/* ============================================================================
 * Curl mock configuration
 * ============================================================================ */

void mock_curl_setopt_set_result(CURLoption option, CURLcode result) {
    if (option < 256) {
        g_mock_state.curl_setopt_results[option] = result;
    }
}

void mock_curl_setopt_set_fail_at(int call_index, CURLoption option, CURLcode result) {
    g_mock_state.curl_setopt_fail_index = call_index;
    g_mock_state.curl_setopt_fail_option = option;
    g_mock_state.curl_setopt_results[option] = result;
}

void mock_curl_init_set_result(CURL* result) {
    g_mock_state.curl_init_result = result;
}

void mock_curl_perform_set_result(CURLcode result) {
    g_mock_state.curl_perform_result = result;
}

/* ============================================================================
 * OpenSSL mock implementations
 * ============================================================================ */

void mock_SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb) {
    g_mock_state.ssl_passwd_cb_call_count++;
    g_mock_state.ssl_passwd_cb_func = cb;
    (void)ctx;
}

void mock_SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u) {
    g_mock_state.ssl_passwd_data_call_count++;
    g_mock_state.ssl_passwd_cb_userdata = u;
    (void)ctx;
}

void mock_OPENSSL_cleanse(void *ptr, size_t len) {
    g_mock_state.openssl_cleanse_call_count++;
    g_mock_state.openssl_cleanse_last_ptr = ptr;
    g_mock_state.openssl_cleanse_last_len = len;
    /* Actually clear the memory for security */
    if (ptr && len > 0) {
        memset(ptr, 0, len);
    }
}

/* ============================================================================
 * OpenSSL mock configuration
 * ============================================================================ */

void mock_ssl_set_passwd_cb_result(int result) {
    g_mock_state.ssl_passwd_cb_result = result;
}

void mock_ssl_set_passwd_data_result(int result) {
    g_mock_state.ssl_passwd_data_result = result;
}

/* ============================================================================
 * Verification functions
 * ============================================================================ */

int mock_get_call_count(mock_type_t type) {
    switch (type) {
        case MOCK_TYPE_CURL_EASY_SETOPT:
            return (int)g_mock_state.curl_setopt_call_count;
        case MOCK_TYPE_CURL_EASY_INIT:
            return (int)g_mock_state.curl_init_call_count;
        case MOCK_TYPE_CURL_EASY_CLEANUP:
            return (int)g_mock_state.curl_cleanup_call_count;
        case MOCK_TYPE_CURL_EASY_PERFORM:
            return (int)g_mock_state.curl_perform_call_count;
        case MOCK_TYPE_SSL_CTX_SET_PASSWD_CB:
            return (int)g_mock_state.ssl_passwd_cb_call_count;
        case MOCK_TYPE_SSL_CTX_SET_PASSWD_DATA:
            return (int)g_mock_state.ssl_passwd_data_call_count;
        case MOCK_TYPE_OPENSSL_CLEANSE:
            return (int)g_mock_state.openssl_cleanse_call_count;
        default:
            return 0;
    }
}

void mock_verify_called(mock_type_t type, int times) {
    int actual = mock_get_call_count(type);
    if (actual != times) {
        printf("  MOCK VERIFICATION FAILED: Expected %d calls, actual %d calls\n",
               times, actual);
    }
}

void mock_verify_called_at_least(mock_type_t type, int times) {
    int actual = mock_get_call_count(type);
    if (actual < times) {
        printf("  MOCK VERIFICATION FAILED: Expected at least %d calls, actual %d calls\n",
               times, actual);
    }
}
