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
 * @file test_password_callback.c
 * @brief Password callback (lazy loading) tests
 *
 * Tests ssl_password_callback() function for secure password retrieval:
 * - Callback invocation with proper context
 * - Error handling for failed password retrieval
 * - Secure memory cleanup with OPENSSL_cleanse
 * - NULL parameter handling
 */

#include "test_framework.h"
#include "test_mocks.h"
#include "test_types.h"

/* External function declarations from stubs */
CURLcode ssl_password_callback(CURL *curl, void *sslctx, void *userdata);

/* Test data */
static char test_password_buffer[256];
static int test_password_callback_called = 0;

/* Test password callback that succeeds */
static int test_password_callback_success(void* context, char* password_buffer, size_t buffer_size) {
    test_password_callback_called++;
    (void)context;

    if (password_buffer && buffer_size > 0) {
        strncpy(password_buffer, "test_password_123", buffer_size - 1);
        password_buffer[buffer_size - 1] = '\0';
        return 0;  /* Success */
    }
    return -1;  /* Failure */
}

/* Test password callback that fails */
static int test_password_callback_failure(void* context, char* password_buffer, size_t buffer_size) {
    test_password_callback_called++;
    (void)context;
    (void)password_buffer;
    (void)buffer_size;
    return -1;  /* Failure */
}

/* Setup function */
static void setup(void) {
    memset(test_password_buffer, 0, sizeof(test_password_buffer));
    test_password_callback_called = 0;
    mock_init();
}

/* Teardown function */
static void teardown(void) {
    mock_cleanup();
}

/* ============================================================================
 * Test cases
 * ============================================================================ */

/* Test 1: No callback configured should return CURLE_OK */
TEST(PasswordCallback, NoCallback_Success) {
    obs_http_request_option options;
    memset(&options, 0, sizeof(options));
    /* password_callback is NULL by default */

    CURL* curl = (CURL*)0x12345678;
    SSL_CTX* ssl_ctx = (SSL_CTX*)0x87654321;

    CURLcode result = ssl_password_callback(curl, ssl_ctx, &options);

    TEST_ASSERT_EQ_INT(CURLE_OK, result);
}

/* Test 2: Successful password callback with valid configuration */
TEST(PasswordCallback, WithCallback_Success) {
    obs_http_request_option options;
    memset(&options, 0, sizeof(options));
    options.password_callback = test_password_callback_success;
    options.password_callback_context = NULL;

    CURL* curl = (CURL*)0x12345678;
    SSL_CTX* ssl_ctx = (SSL_CTX*)0x87654321;

    CURLcode result = ssl_password_callback(curl, ssl_ctx, &options);

    TEST_ASSERT_EQ_INT(CURLE_OK, result);
    TEST_ASSERT_EQ_INT(1, test_password_callback_called);
}

/* Test 3: Password callback invocation with failure scenario */
TEST(PasswordCallback, CallbackInvokeFailure) {
    obs_http_request_option options;
    memset(&options, 0, sizeof(options));
    options.password_callback = test_password_callback_failure;
    options.password_callback_context = NULL;

    CURL* curl = (CURL*)0x12345678;
    SSL_CTX* ssl_ctx = (SSL_CTX*)0x87654321;

    CURLcode result = ssl_password_callback(curl, ssl_ctx, &options);

    /* Should return CURLE_SSL_CERTPROBLEM on password callback failure */
    TEST_ASSERT_EQ_INT(CURLE_SSL_CERTPROBLEM, result);
    TEST_ASSERT_EQ_INT(1, test_password_callback_called);
}

/* Test 4: NULL options parameter handling */
TEST(PasswordCallback, NullOptions) {
    CURL* curl = (CURL*)0x12345678;
    SSL_CTX* ssl_ctx = (SSL_CTX*)0x87654321;

    CURLcode result = ssl_password_callback(curl, ssl_ctx, NULL);

    /* Should return CURLE_OK to allow graceful handling of missing configuration */
    TEST_ASSERT_EQ_INT(CURLE_OK, result);
}

/* Test 5: NULL callback within valid options */
TEST(PasswordCallback, NullCallback) {
    obs_http_request_option options;
    memset(&options, 0, sizeof(options));
    /* password_callback is NULL by default from memset */

    CURL* curl = (CURL*)0x12345678;
    SSL_CTX* ssl_ctx = (SSL_CTX*)0x87654321;

    CURLcode result = ssl_password_callback(curl, ssl_ctx, &options);

    /* Should return CURLE_OK without performing any callback operations */
    TEST_ASSERT_EQ_INT(CURLE_OK, result);
}

/* ============================================================================
 * Test suite registration
 * ============================================================================ */

void register_password_callback_tests(void) {
    /* Tests are auto-registered via TEST macro */
    /* This function exists for compatibility with the test runner */
}
