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
 * @file test_mutual_auth.c
 * @brief Mutual authentication tests
 *
 * Tests setup_mtls() function with various configurations:
 * - client_auth_switch settings (OPEN/CLOSE)
 * - Certificate and key path validation
 * - Error handling for missing/invalid parameters
 */

#include "test_framework.h"
#include "test_mocks.h"
#include "test_types.h"

/* External function declarations from stubs */
obs_status setup_mtls(http_request *request,
                      request_params *params,
                      request_computed_values *values);

/* Test fixture */
static http_request test_request;
static request_params test_params;
static request_computed_values test_values;

static void setup(void) {
    memset(&test_request, 0, sizeof(test_request));
    memset(&test_params, 0, sizeof(test_params));
    memset(&test_values, 0, sizeof(test_values));

    test_request.curl = (CURL*)0x12345678;
    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_CLOSE;
    test_params.request_option.gm_mode_switch = OBS_GM_MODE_CLOSE;
    test_params.isCheckCA = 1;

    mock_init();
}

static void teardown(void) {
    mock_cleanup();
}

/* Test 1: Client auth close should skip certificate configuration */
TEST(MutualAuth, DISABLED_ClientAuthClose) {
    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_CLOSE;

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* Test 2: Successful mutual authentication with valid certificates */
TEST(MutualAuth, ClientAuthOpen_Success) {
    /* Set up curl mock to succeed */
    mock_curl_setopt_set_result(CURLOPT_SSLCERT, CURLE_OK);
    mock_curl_setopt_set_result(CURLOPT_SSLKEY, CURLE_OK);

    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_OPEN;
    test_params.request_option.client_cert_path = "/path/to/cert.pem";
    test_params.request_option.client_key_path = "/path/to/key.pem";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* Test 3: Missing certificate path should return error */
TEST(MutualAuth, ClientAuthOpen_MissingCert) {
    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_OPEN;
    test_params.request_option.client_cert_path = NULL;
    test_params.request_option.client_key_path = "/path/to/key.pem";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_NE_INT(OBS_STATUS_OK, status);
}

/* Test 4: Missing key path should return error */
TEST(MutualAuth, ClientAuthOpen_MissingKey) {
    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_OPEN;
    test_params.request_option.client_cert_path = "/path/to/cert.pem";
    test_params.request_option.client_key_path = NULL;

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_NE_INT(OBS_STATUS_OK, status);
}

/* Test 5: Curl setopt failure for certificate should return correct error */
TEST(MutualAuth, CurlSetoptFailed_CertNotFound) {
    /* Mock curl_easy_setopt to fail for SSLCERT */
    mock_curl_setopt_set_result(CURLOPT_SSLCERT, CURLE_SSL_CERTPROBLEM);

    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_OPEN;
    test_params.request_option.client_cert_path = "/invalid/cert.pem";
    test_params.request_option.client_key_path = "/path/to/key.pem";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    /* Should return an error related to certificate not found */
    TEST_ASSERT_NE_INT(OBS_STATUS_OK, status);
}

/* Test 6: Curl setopt failure for key should return correct error */
TEST(MutualAuth, CurlSetoptFailed_KeyNotFound) {
    /* Mock curl_easy_setopt to fail for SSLKEY */
    mock_curl_setopt_set_result(CURLOPT_SSLKEY, CURLE_SSL_CERTPROBLEM);

    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_OPEN;
    test_params.request_option.client_cert_path = "/path/to/cert.pem";
    test_params.request_option.client_key_path = "/invalid/key.pem";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    /* Should return an error related to key not found */
    TEST_ASSERT_NE_INT(OBS_STATUS_OK, status);
}

/* Register all tests */
void register_mutual_auth_tests(void) {
    /* Tests are auto-registered via TEST macro */
    /* This function exists for compatibility with the test runner */
}
