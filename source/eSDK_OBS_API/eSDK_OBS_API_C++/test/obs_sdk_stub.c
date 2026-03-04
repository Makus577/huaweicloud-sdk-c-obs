/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * OBS SDK Stub Implementation for Testing
 * This file provides stub implementations of OBS SDK functions for testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eSDKOBS.h"

/* Stub obs_options structure */
typedef struct stub_obs_options {
    obs_http_request_option request_option;
    char *endpoint;
    char *access_key;
    char *secret_key;
} stub_obs_options;

/* Create new options */
void *obs_options_new(void) {
    stub_obs_options *options = (stub_obs_options *)calloc(1, sizeof(stub_obs_options));
    if (options) {
        options->request_option.mutual_auth = OBS_MUTUAL_SSL_CLOSE;
        options->request_option.gm_mode = OBS_GM_MODE_CLOSE;
        options->request_option.min_tls_version = TLS1_2_VERSION;
        options->request_option.max_tls_version = TLS1_3_VERSION;
    }
    return options;
}

/* Destroy options */
void obs_options_destroy(void *options) {
    if (options) {
        stub_obs_options *opts = (stub_obs_options *)options;
        free(opts->endpoint);
        free(opts->access_key);
        free(opts->secret_key);
        free(opts);
    }
}

/* Set server certificate path */
void obs_options_set_server_cert_path(void *options, const char *path) {
    if (options && path) {
        stub_obs_options *opts = (stub_obs_options *)options;
        strncpy(opts->request_option.ca_path, path, sizeof(opts->request_option.ca_path) - 1);
    }
}

/* Set mutual SSL switch */
void obs_options_set_mutual_ssl_switch(void *options, int value) {
    if (options) {
        stub_obs_options *opts = (stub_obs_options *)options;
        opts->request_option.mutual_auth = value ? OBS_MUTUAL_SSL_OPEN : OBS_MUTUAL_SSL_CLOSE;
    }
}

/* Set client certificate path */
void obs_options_set_client_cert_path(void *options, const char *path) {
    if (options && path) {
        stub_obs_options *opts = (stub_obs_options *)options;
        strncpy(opts->request_option.cert_path, path, sizeof(opts->request_option.cert_path) - 1);
    }
}

/* Set client key path */
void obs_options_set_client_key_path(void *options, const char *path) {
    if (options && path) {
        stub_obs_options *opts = (stub_obs_options *)options;
        strncpy(opts->request_option.key_path, path, sizeof(opts->request_option.key_path) - 1);
    }
}

/* Set client key password */
void obs_options_set_client_key_password(void *options, const char *password) {
    if (options && password) {
        stub_obs_options *opts = (stub_obs_options *)options;
        strncpy(opts->request_option.key_password, password, sizeof(opts->request_option.key_password) - 1);
    }
}

/* Set client encryption certificate path (for GM dual cert mode) */
void obs_options_set_client_enc_cert_path(void *options, const char *path) {
    if (options && path) {
        stub_obs_options *opts = (stub_obs_options *)options;
        strncpy(opts->request_option.enc_cert_path, path, sizeof(opts->request_option.enc_cert_path) - 1);
    }
}

/* Set client encryption key path (for GM dual cert mode) */
void obs_options_set_client_enc_key_path(void *options, const char *path) {
    if (options && path) {
        stub_obs_options *opts = (stub_obs_options *)options;
        strncpy(opts->request_option.enc_key_path, path, sizeof(opts->request_option.enc_key_path) - 1);
    }
}

/* Set GM mode switch */
void obs_options_set_gm_mode_switch(void *options, int value) {
    if (options) {
        stub_obs_options *opts = (stub_obs_options *)options;
        opts->request_option.gm_mode = value ? OBS_GM_MODE_OPEN : OBS_GM_MODE_CLOSE;
    }
}

/* Set SSL minimum version */
void obs_options_set_ssl_min_version(void *options, int version) {
    if (options) {
        stub_obs_options *opts = (stub_obs_options *)options;
        opts->request_option.min_tls_version = version;
    }
}

/* Set SSL maximum version */
void obs_options_set_ssl_max_version(void *options, int version) {
    if (options) {
        stub_obs_options *opts = (stub_obs_options *)options;
        opts->request_option.max_tls_version = version;
    }
}

/* Set SSL cipher list */
void obs_options_set_ssl_cipher_list(void *options, const char *ciphers) {
    if (options && ciphers) {
        stub_obs_options *opts = (stub_obs_options *)options;
        strncpy(opts->request_option.cipher_list, ciphers, sizeof(opts->request_option.cipher_list) - 1);
    }
}
