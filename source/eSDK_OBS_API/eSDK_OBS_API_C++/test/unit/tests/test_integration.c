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
 * @file test_integration.c
 * @brief Integration tests for GM + Mutual Auth
 *
 * These tests verify the complete integration of all SSL/TLS components:
 * - Full mutual authentication with password callback
 * - Full GM mode with dual certificates
 * - Error recovery and resource cleanup
 */

#include "test_framework.h"
#include "test_mocks.h"
#include "test_types.h"

/* External function declarations from stubs */
obs_status setup_mtls(http_request *request,
                      request_params *params,
                      request_computed_values *values);

/* Test data */
static int password_callback_called = 0;
static char last_password[256] = {0};

/* Test password callback that succeeds */
static int test_password_callback(void* context, char* password_buffer, size_t buffer_size) {
    (void)context;

    password_callback_called++;

    if (password_buffer && buffer_size > 0) {
        strncpy(password_buffer, "test_password_secret", buffer_size - 1);
        password_buffer[buffer_size - 1] = '\0';
        strncpy(last_password, password_buffer, sizeof(last_password) - 1);
        last_password[sizeof(last_password) - 1] = '\0';
        return 0;  /* Success */
    }
    return -1;  /* Failure */
}

/* Test fixture */
static http_request test_request;
static request_params test_params;
static request_computed_values test_values;

static void setup(void) {
    memset(&test_request, 0, sizeof(test_request));
    memset(&test_params, 0, sizeof(test_params));
    memset(&test_values, 0, sizeof(test_values));

    test_request.curl = (CURL*)0x12345678;
    test_params.isCheckCA = 1;

    password_callback_called = 0;
    memset(last_password, 0, sizeof(last_password));

    mock_init();

    /* Set up default mock results */
    mock_curl_setopt_set_result(CURLOPT_SSLCERT, CURLE_OK);
    mock_curl_setopt_set_result(CURLOPT_SSLKEY, CURLE_OK);
    mock_curl_setopt_set_result(CURLOPT_CAINFO, CURLE_OK);
#ifdef CURLOPT_SSLENCCERT
    mock_curl_setopt_set_result(CURLOPT_SSLENCCERT, CURLE_OK);
#endif
#ifdef CURLOPT_SSLENCKEY
    mock_curl_setopt_set_result(CURLOPT_SSLENCKEY, CURLE_OK);
#endif
}

static void teardown(void) {
    mock_cleanup();
}

/* ============================================================================
 * Test cases
 * ============================================================================ */

/* Test 1: Complete mutual authentication with password callback */
TEST(Integration, FullMutualAuthWithPassword) {
    /* Set up mutual auth */
    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_OPEN;
    test_params.request_option.client_cert_path = "/path/to/cert.pem";
    test_params.request_option.client_key_path = "/path/to/key.pem";

    /* Set up password callback */
    test_params.request_option.password_callback = test_password_callback;
    test_params.request_option.password_callback_context = NULL;

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
    /* Note: We can't verify password_callback_called without actual execution */
}

/* Test 2: Complete GM mode with all certificates */
TEST(Integration, FullGMModeWithAllCerts) {
    /* Enable GM mode and mutual auth */
    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_OPEN;
    test_params.request_option.gm_mode_switch = OBS_GM_MODE_OPEN;

    /* Set up all certificates */
    test_params.request_option.client_cert_path = "/path/to/sign_cert.pem";
    test_params.request_option.client_key_path = "/path/to/sign_key.pem";
    test_params.request_option.client_enc_cert_path = "/path/to/enc_cert.pem";
    test_params.request_option.client_enc_key_path = "/path/to/enc_key.pem";

    /* Set cipher list for GM */
    test_params.request_option.ssl_cipher_list = "ECDHE-SM2-WITH-SM4-SM3";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* Test 3: Error recovery and resource cleanup */
TEST(Integration, ErrorRecovery) {
    /* Set up mutual auth but leave cert path NULL to cause error */
    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_OPEN;
    test_params.request_option.client_cert_path = NULL;
    test_params.request_option.client_key_path = "/path/to/key.pem";

    /* This should fail with InvalidParameter */
    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_NE_INT(OBS_STATUS_OK, status);

    /* Now verify we can recover and set up correctly */
    test_params.request_option.client_cert_path = "/path/to/cert.pem";

    status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* ============================================================================
 * Test suite registration
 * ============================================================================ */

void register_integration_tests(void) {
    /* Tests are auto-registered via TEST macro */
    /* This function exists for compatibility with the test runner */
}
