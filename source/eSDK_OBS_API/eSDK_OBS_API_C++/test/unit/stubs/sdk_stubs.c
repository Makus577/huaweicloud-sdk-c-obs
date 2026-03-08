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
 * @file sdk_stubs.c
 * @brief Stub implementations of SDK functions for testing
 *
 * These stubs provide minimal implementations of SDK functions
 * that are required for linking tests without the full SDK.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <openssl/ssl.h>

/* Include test types */
#include "../src/test_types.h"

/* Stub implementations of SDK functions */

obs_status setup_mtls(http_request *request,
    const request_params *params,
    const request_computed_values *values)
{
    (void)request;
    (void)values;

    if (!params) {
        return OBS_STATUS_InvalidParameter;
    }

    /* Check mutual auth configuration */
    if (params->request_option.client_auth_switch == OBS_CLIENT_AUTH_OPEN) {
        if (!params->request_option.client_cert_path ||
            !params->request_option.client_key_path) {
            return OBS_STATUS_InvalidParameter;
        }
    }

    /* Check GM mode configuration */
    if (params->request_option.gm_mode_switch == OBS_GM_MODE_OPEN) {
        if (!params->request_option.client_enc_cert_path ||
            !params->request_option.client_enc_key_path) {
            return OBS_STATUS_GM_EncCertNotFound;
        }
    }

    return OBS_STATUS_OK;
}

obs_status setup_CA(http_request *request,
    const request_params *params,
    const request_computed_values *values)
{
    (void)request;
    (void)params;
    (void)values;

    return OBS_STATUS_OK;
}

obs_status setup_CheckCA(http_request *request,
    const request_params *params,
    const request_computed_values *values)
{
    obs_status status;

    /* Call setup_mtls first */
    status = setup_mtls(request, params, values);
    if (status != OBS_STATUS_OK) {
        return status;
    }

    /* Call setup_CA if isCheckCA is set */
    if (params->isCheckCA) {
        return setup_CA(request, params, values);
    }

    return OBS_STATUS_OK;
}

CURLcode ssl_password_callback(CURL *curl, void *sslctx, void *userdata)
{
    obs_http_request_option *options = (obs_http_request_option *)userdata;

    (void)curl;
    (void)sslctx;

    if (!options || !options->password_callback) {
        /* No password callback set, skip */
        return CURLE_OK;
    }

    /* Call the password callback */
    char password_buffer[256];
    int ret = options->password_callback(
        options->password_callback_context,
        password_buffer,
        sizeof(password_buffer)
    );

    if (ret != 0) {
        /* Password callback failed */
        return CURLE_SSL_CERTPROBLEM;
    }

    /* Success - password retrieved */
    /* In real implementation, this would set the password in SSL_CTX */

    return CURLE_OK;
}
