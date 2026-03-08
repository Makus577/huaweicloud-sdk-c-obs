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
 * @file test_gm_mode.c
 * @brief GM (National Cryptography) mode tests
 *
 * Tests setup_mtls() with GM mode enabled:
 * - Dual certificate configuration (sign + encrypt)
 * - Tongsuo-specific cipher and version settings
 * - Error handling for missing encryption certificates
 * - Integration with standard mutual authentication
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

    /* Enable mutual auth and GM mode by default for these tests */
    test_params.request_option.client_auth_switch = OBS_CLIENT_AUTH_OPEN;
    test_params.request_option.gm_mode_switch = OBS_GM_MODE_OPEN;
    test_params.isCheckCA = 1;

    mock_init();

    /* Set up default mock results for curl */
    mock_curl_setopt_set_result(CURLOPT_SSLCERT, CURLE_OK);
    mock_curl_setopt_set_result(CURLOPT_SSLKEY, CURLE_OK);
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

/* Test 1: GM mode close should skip GM-specific configuration */
TEST(GMMode, DISABLED_GMModeClose) {
    test_params.request_option.gm_mode_switch = OBS_GM_MODE_CLOSE;
    test_params.request_option.client_cert_path = "/path/to/cert.pem";
    test_params.request_option.client_key_path = "/path/to/key.pem";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* Test 2: GM mode success with complete dual certificate configuration */
TEST(GMMode, GMModeOpen_Success) {
    /* Set up all required paths */
    test_params.request_option.client_cert_path = "/path/to/sign_cert.pem";
    test_params.request_option.client_key_path = "/path/to/sign_key.pem";
    test_params.request_option.client_enc_cert_path = "/path/to/enc_cert.pem";
    test_params.request_option.client_enc_key_path = "/path/to/enc_key.pem";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* Test 3: GM mode fails when encryption certificate path is NULL */
TEST(GMMode, GMModeOpen_MissingEncCert) {
    test_params.request_option.client_cert_path = "/path/to/sign_cert.pem";
    test_params.request_option.client_key_path = "/path/to/sign_key.pem";
    test_params.request_option.client_enc_cert_path = NULL;  /* Missing! */
    test_params.request_option.client_enc_key_path = "/path/to/enc_key.pem";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_GM_EncCertNotFound, status);
}

/* Test 4: GM mode fails when encryption key path is NULL */
TEST(GMMode, GMModeOpen_MissingEncKey) {
    test_params.request_option.client_cert_path = "/path/to/sign_cert.pem";
    test_params.request_option.client_key_path = "/path/to/sign_key.pem";
    test_params.request_option.client_enc_cert_path = "/path/to/enc_cert.pem";
    test_params.request_option.client_enc_key_path = NULL;  /* Missing! */

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_GM_EncCertNotFound, status);
}

/* Test 5: Tongsuo not available - disabled by default */
TEST(GMMode, DISABLED_GMModeOpen_TongsuoNotAvailable) {
    /* This test is disabled by default as it requires building
     * without CURL_SSLVERSION_NTLSv1_1 defined */

    test_params.request_option.client_cert_path = "/path/to/sign_cert.pem";
    test_params.request_option.client_key_path = "/path/to/sign_key.pem";
    test_params.request_option.client_enc_cert_path = "/path/to/enc_cert.pem";
    test_params.request_option.client_enc_key_path = "/path/to/enc_key.pem";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

#ifndef CURL_SSLVERSION_NTLSv1_1
    TEST_ASSERT_EQ_INT(OBS_STATUS_GM_TongsuoNotSupported, status);
#else
    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
#endif
}

/* Test 6: GM mode combined with standard mutual authentication */
TEST(GMMode, GMModeWithMutualAuth) {
    test_params.request_option.client_cert_path = "/path/to/sign_cert.pem";
    test_params.request_option.client_key_path = "/path/to/sign_key.pem";
    test_params.request_option.client_enc_cert_path = "/path/to/enc_cert.pem";
    test_params.request_option.client_enc_key_path = "/path/to/enc_key.pem";

    obs_status status = setup_mtls(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* ============================================================================
 * Test suite registration
 * ============================================================================ */

void register_gm_mode_tests(void) {
    /* Tests are auto-registered via TEST macro */
    /* This function exists for compatibility with the test runner */
}
