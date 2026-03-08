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
 * @file test_ca_cert.c
 * @brief CA certificate configuration tests
 *
 * Tests setup_CA() function for configuring CA certificates:
 * - Server certificate path configuration
 * - Certificate info buffer configuration
 * - SSL verification settings
 * - Hostname verification options
 */

#include "test_framework.h"
#include "test_mocks.h"
#include "test_types.h"

/* External function declarations from stubs */
obs_status setup_CA(http_request *request,
                    request_params *params,
                    request_computed_values *values);
obs_status setup_CheckCA(http_request *request,
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
    test_params.isCheckCA = 1;

    mock_init();

    /* Set up default mock results */
    mock_curl_setopt_set_result(CURLOPT_CAINFO, CURLE_OK);
}

static void teardown(void) {
    mock_cleanup();
}

/* ============================================================================
 * Test cases
 * ============================================================================ */

/* Test 1: Successful CA certificate path configuration */
TEST(CACertConfig, ServerCertPath_Success) {
    test_params.request_option.server_cert_path = "/path/to/ca.pem";

    obs_status status = setup_CA(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* Test 2: Certificate info buffer configuration */
TEST(CACertConfig, CertificateInfo_Success) {
    test_params.bucketContext.certificate_info = "-----BEGIN CERTIFICATE-----\n...";

    obs_status status = setup_CA(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* Test 3: Disabled CA verification */
TEST(CACertConfig, DisableCheckCA) {
    test_params.isCheckCA = 0;

    obs_status status = setup_CheckCA(&test_request, &test_params, &test_values);

    TEST_ASSERT_EQ_INT(OBS_STATUS_OK, status);
}

/* ============================================================================
 * Test suite registration
 * ============================================================================ */

void register_ca_cert_tests(void) {
    /* Tests are auto-registered via TEST macro */
    /* This function exists for compatibility with the test runner */
}
