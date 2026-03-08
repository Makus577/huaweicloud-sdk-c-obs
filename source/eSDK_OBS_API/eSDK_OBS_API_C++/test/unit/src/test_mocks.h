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
 * @file test_mocks.h
 * @brief Mock framework for unit testing
 *
 * This is a simple C mocking framework that allows:
 * - Mocking function calls
 * - Setting return values
 * - Verifying call counts
 * - Resetting mocks between tests
 */

#ifndef TEST_MOCKS_H
#define TEST_MOCKS_H

#include <stddef.h>
#include <curl/curl.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of curl options we track */
#define MAX_CURL_OPTIONS 256

/* Mock types for verification */
typedef enum {
    MOCK_TYPE_CURL_EASY_SETOPT,
    MOCK_TYPE_CURL_EASY_INIT,
    MOCK_TYPE_CURL_EASY_CLEANUP,
    MOCK_TYPE_CURL_EASY_PERFORM,
    MOCK_TYPE_SSL_CTX_SET_PASSWD_CB,
    MOCK_TYPE_SSL_CTX_SET_PASSWD_DATA,
    MOCK_TYPE_OPENSSL_CLEANSE,
    MOCK_TYPE_CUSTOM
} mock_type_t;

/* Mock state structure */
typedef struct {
    int initialized;

    /* Curl mock state */
    CURLcode curl_setopt_results[MAX_CURL_OPTIONS];
    size_t curl_setopt_call_count;
    int curl_setopt_fail_index;
    CURLoption curl_setopt_fail_option;

    CURL* curl_init_result;
    size_t curl_init_call_count;

    size_t curl_cleanup_call_count;

    CURLcode curl_perform_result;
    size_t curl_perform_call_count;

    /* OpenSSL mock state */
    int ssl_passwd_cb_result;
    size_t ssl_passwd_cb_call_count;
    pem_password_cb* ssl_passwd_cb_func;

    int ssl_passwd_data_result;
    size_t ssl_passwd_data_call_count;
    void* ssl_passwd_cb_userdata;

    size_t openssl_cleanse_call_count;
    void* openssl_cleanse_last_ptr;
    size_t openssl_cleanse_last_len;

} mock_state_t;

/* Global mock state */
extern mock_state_t g_mock_state;

/* ============================================================================
 * Mock initialization and cleanup
 * ============================================================================ */

void mock_init(void);
void mock_cleanup(void);
void mock_reset(void);

/* ============================================================================
 * Curl mock functions
 * ============================================================================ */

CURLcode mock_curl_easy_setopt(CURL *curl, CURLoption option, ...);
CURL* mock_curl_easy_init(void);
void mock_curl_easy_cleanup(CURL *curl);
CURLcode mock_curl_easy_perform(CURL *curl);

/* Configure mock results */
void mock_curl_setopt_set_result(CURLoption option, CURLcode result);
void mock_curl_setopt_set_fail_at(int call_index, CURLoption option, CURLcode result);
void mock_curl_init_set_result(CURL* result);
void mock_curl_perform_set_result(CURLcode result);

/* ============================================================================
 * OpenSSL mock functions
 * ============================================================================ */

void mock_SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
void mock_SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
void mock_OPENSSL_cleanse(void *ptr, size_t len);

/* Configure OpenSSL mock results */
void mock_ssl_set_passwd_cb_result(int result);
void mock_ssl_set_passwd_data_result(int result);

/* ============================================================================
 * Verification functions
 * ============================================================================ */

int mock_get_call_count(mock_type_t type);
void mock_verify_called(mock_type_t type, int times);
void mock_verify_called_at_least(mock_type_t type, int times);

/* ============================================================================
 * Assertion macros for tests
 * ============================================================================ */

#define MOCK_ASSERT_CALLED(type, times) \
    do { \
        int actual = mock_get_call_count(type); \
        if (actual != (times)) { \
            printf("  MOCK VERIFICATION FAILED: Expected %s to be called %d times, but was called %d times\n", \
                   #type, (times), actual); \
        } \
    } while(0)

#define MOCK_ASSERT_CALLED_AT_LEAST(type, times) \
    do { \
        int actual = mock_get_call_count(type); \
        if (actual < (times)) { \
            printf("  MOCK VERIFICATION FAILED: Expected %s to be called at least %d times, but was called %d times\n", \
                   #type, (times), actual); \
        } \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif /* TEST_MOCKS_H */
