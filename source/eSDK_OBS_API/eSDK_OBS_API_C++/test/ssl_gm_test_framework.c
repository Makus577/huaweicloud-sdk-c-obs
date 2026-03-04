/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ssl_gm_test_framework.c
 * @brief Test framework implementation for SSL/TLS and GM tests
 */

#include "ssl_gm_test_framework.h"

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

/* ============================================================================
 * Global Variables
 * ============================================================================ */

test_config_t g_test_config = {
    .test_dir = DEFAULT_CERT_DIR,
    .cert_dir = DEFAULT_CERT_DIR "/certs",
    .temp_dir = DEFAULT_CERT_DIR "/temp",
    .verbose = false,
    .generate_certs = true,
    .test_timeout = 300,
    .obs_endpoint = "",
    .obs_bucket = ""
};

test_suite_t *g_current_suite = NULL;
test_case_t *g_current_test = NULL;

/* ============================================================================
 * Static Variables for Colors
 * ============================================================================ */

static const char *color_reset = "\033[0m";
static const char *color_red = "\033[31m";
static const char *color_green = "\033[32m";
static const char *color_yellow = "\033[33m";
static const char *color_blue = "\033[34m";

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

static double get_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void mkdir_recursive(const char *path) {
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

/* ============================================================================
 * Test Framework Implementation
 * ============================================================================ */

int test_framework_init(test_config_t *config) {
    if (config) {
        memcpy(&g_test_config, config, sizeof(test_config_t));
    }

    /* Create directories */
    mkdir_recursive(g_test_config.test_dir);
    mkdir_recursive(g_test_config.cert_dir);
    mkdir_recursive(g_test_config.temp_dir);

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    test_log(2, "Test framework initialized\n");
    test_log(2, "Test directory: %s\n", g_test_config.test_dir);
    test_log(2, "Certificate directory: %s\n", g_test_config.cert_dir);

    return 0;
}

void test_framework_cleanup(void) {
    /* Cleanup OpenSSL */
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    test_log(2, "Test framework cleaned up\n");
}

test_suite_t *test_suite_create(const char *name, const char *description) {
    test_suite_t *suite = (test_suite_t *)calloc(1, sizeof(test_suite_t));
    if (!suite) {
        return NULL;
    }

    strncpy(suite->name, name, MAX_TEST_NAME_LEN - 1);
    if (description) {
        strncpy(suite->description, description, sizeof(suite->description) - 1);
    }

    suite->test_count = 0;
    suite->tests_passed = 0;
    suite->tests_failed = 0;
    suite->tests_skipped = 0;
    suite->total_execution_time = 0.0;

    return suite;
}

void test_suite_destroy(test_suite_t *suite) {
    if (!suite) {
        return;
    }

    for (int i = 0; i < suite->test_count; i++) {
        if (suite->tests[i]) {
            free(suite->tests[i]);
        }
    }

    free(suite);
}

int test_suite_add_test(test_suite_t *suite, const char *name,
                        const char *description,
                        void (*test_func)(test_case_t *tc)) {
    if (!suite || !test_func || suite->test_count >= MAX_TEST_CASES) {
        return -1;
    }

    test_case_t *test = (test_case_t *)calloc(1, sizeof(test_case_t));
    if (!test) {
        return -1;
    }

    strncpy(test->name, name, MAX_TEST_NAME_LEN - 1);
    if (description) {
        strncpy(test->description, description, sizeof(test->description) - 1);
    }

    test->test_func = test_func;
    test->result = TEST_NOT_RUN;
    test->assertions_total = 0;
    test->assertions_passed = 0;
    test->assertions_failed = 0;
    test->error_msg[0] = '\0';
    test->execution_time = 0.0;
    test->user_data = NULL;

    suite->tests[suite->test_count++] = test;

    return 0;
}

int test_suite_run(test_suite_t *suite) {
    if (!suite) {
        return -1;
    }

    g_current_suite = suite;

    test_print_color(4, "\n========================================\n");
    test_print_color(4, "Test Suite: %s\n", suite->name);
    if (suite->description[0]) {
        test_print_color(4, "Description: %s\n", suite->description);
    }
    test_print_color(4, "========================================\n\n");

    double suite_start = get_time();

    if (suite->setup) {
        suite->setup();
    }

    for (int i = 0; i < suite->test_count; i++) {
        test_case_t *test = suite->tests[i];
        g_current_test = test;

        test_log(2, "[%d/%d] Running: %s\n", i + 1, suite->test_count, test->name);

        double test_start = get_time();

        /* Run the test */
        test->result = TEST_NOT_RUN;
        test->test_func(test);

        /* If no explicit result set, check assertions */
        if (test->result == TEST_NOT_RUN) {
            if (test->assertions_failed > 0) {
                test->result = TEST_FAILED;
            } else {
                test->result = TEST_PASSED;
            }
        }

        test->execution_time = get_time() - test_start;
        suite->total_execution_time += test->execution_time;

        /* Update statistics */
        switch (test->result) {
            case TEST_PASSED:
                suite->tests_passed++;
                test_print_color(2, "  [PASS] %s (%.3fs)\n",
                                 test->name, test->execution_time);
                break;
            case TEST_FAILED:
                suite->tests_failed++;
                test_print_color(1, "  [FAIL] %s (%.3fs)\n",
                                 test->name, test->execution_time);
                if (test->error_msg[0]) {
                    test_print_color(1, "    Error: %s\n", test->error_msg);
                }
                break;
            case TEST_SKIPPED:
                suite->tests_skipped++;
                test_print_color(3, "  [SKIP] %s\n", test->name);
                if (test->error_msg[0]) {
                    test_print_color(3, "    Reason: %s\n", test->error_msg);
                }
                break;
            default:
                break;
        }
    }

    if (suite->teardown) {
        suite->teardown();
    }

    suite->total_execution_time = get_time() - suite_start;
    g_current_suite = NULL;
    g_current_test = NULL;

    return suite->tests_failed;
}

void test_suite_print_summary(const test_suite_t *suite) {
    if (!suite) {
        return;
    }

    test_print_color(4, "\n========================================\n");
    test_print_color(4, "Test Summary: %s\n", suite->name);
    test_print_color(4, "========================================\n");
    test_print_color(2, "  Passed:  %d/%d\n", suite->tests_passed, suite->test_count);
    test_print_color(1, "  Failed:  %d/%d\n", suite->tests_failed, suite->test_count);
    test_print_color(3, "  Skipped: %d/%d\n", suite->tests_skipped, suite->test_count);
    test_print_color(4, "  Total Time: %.3fs\n", suite->total_execution_time);
    test_print_color(4, "========================================\n\n");
}

/* ============================================================================
 * Assertion Implementation
 * ============================================================================ */

void test_assert_impl(bool condition, const char *file, int line,
                      const char *fmt, ...) {
    if (!g_current_test) {
        return;
    }

    g_current_test->assertions_total++;

    if (condition) {
        g_current_test->assertions_passed++;
    } else {
        g_current_test->assertions_failed++;

        va_list args;
        va_start(args, fmt);
        vsnprintf(g_current_test->error_msg, MAX_ERROR_MSG_LEN, fmt, args);
        va_end(args);

        if (g_test_config.verbose) {
            test_print_color(1, "Assertion failed at %s:%d - %s\n",
                             file, line, g_current_test->error_msg);
        }
    }
}

void test_assert_str_eq_impl(const char *expected, const char *actual,
                            const char *file, int line) {
    (void)file;
    (void)line;

    if (!expected) {
        expected = "(null)";
    }
    if (!actual) {
        actual = "(null)";
    }

    bool equal = (strcmp(expected, actual) == 0);
    test_assert_impl(equal, file, line,
                     "String comparison failed:\n  Expected: '%s'\n  Actual: '%s'",
                     expected, actual);
}

void test_assert_int_eq_impl(long expected, long actual,
                            const char *file, int line) {
    (void)file;
    (void)line;

    bool equal = (expected == actual);
    test_assert_impl(equal, file, line,
                     "Integer comparison failed:\n  Expected: %ld\n  Actual: %ld",
                     expected, actual);
}

/* ============================================================================
 * Logging and Reporting
 * ============================================================================ */

void test_set_verbose(bool verbose) {
    g_test_config.verbose = verbose;
}

void test_log(int level, const char *fmt, ...) {
    if (level > 2 && !g_test_config.verbose) {
        return;
    }

    const char *prefix = "";
    int color = 0;

    switch (level) {
        case 0: /* ERROR */
            prefix = "[ERROR] ";
            color = 1;
            break;
        case 1: /* WARN */
            prefix = "[WARN] ";
            color = 3;
            break;
        case 2: /* INFO */
            prefix = "[INFO] ";
            color = 4;
            break;
        case 3: /* DEBUG */
            prefix = "[DEBUG] ";
            color = 0;
            break;
    }

    va_list args;
    va_start(args, fmt);

    if (color > 0) {
        test_print_color(color, "%s", prefix);
    } else {
        printf("%s", prefix);
    }

    vprintf(fmt, args);
    va_end(args);
}

void test_print_color(int color, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    const char *color_code = color_reset;
    switch (color) {
        case 1: color_code = color_red; break;
        case 2: color_code = color_green; break;
        case 3: color_code = color_yellow; break;
        case 4: color_code = color_blue; break;
    }

    printf("%s", color_code);
    vprintf(fmt, args);
    printf("%s", color_reset);
    fflush(stdout);

    va_end(args);
}

/* ============================================================================
 * Certificate Utilities Implementation
 * ============================================================================ */

int test_cert_init_directory(void) {
    mkdir_recursive(g_test_config.cert_dir);
    mkdir_recursive(g_test_config.temp_dir);
    return 0;
}

void test_cert_cleanup_directory(void) {
    /* Note: In production, this would clean up the directories */
    /* For testing, we keep them for debugging purposes */
}

int test_cert_generate(test_cert_info_t *cert_info, const char *type,
                       int valid_days) {
    if (!cert_info || !type) {
        return -1;
    }

    memset(cert_info, 0, sizeof(test_cert_info_t));
    cert_info->is_gm = (strcmp(type, "sm2") == 0);

    /* Generate file paths */
    snprintf(cert_info->cert_path, sizeof(cert_info->cert_path),
             "%s/%s_cert.pem", g_test_config.cert_dir, type);
    snprintf(cert_info->key_path, sizeof(cert_info->key_path),
             "%s/%s_key.pem", g_test_config.cert_dir, type);
    snprintf(cert_info->ca_path, sizeof(cert_info->ca_path),
             "%s/%s_ca.pem", g_test_config.cert_dir, type);

    if (cert_info->is_gm) {
        snprintf(cert_info->enc_cert_path, sizeof(cert_info->enc_cert_path),
                 "%s/%s_enc_cert.pem", g_test_config.cert_dir, type);
        snprintf(cert_info->enc_key_path, sizeof(cert_info->enc_key_path),
                 "%s/%s_enc_key.pem", g_test_config.cert_dir, type);
        cert_info->has_enc_cert = true;
    }

    /* Set validity period */
    cert_info->valid_from = time(NULL);
    cert_info->valid_until = cert_info->valid_from + (valid_days * 24 * 3600);

    /* Note: In a real implementation, this would generate actual certificates.
     * For the test framework, we create placeholder files.
     * Actual certificate generation would use OpenSSL APIs or system calls.
     */

    FILE *f;
    f = fopen(cert_info->cert_path, "w");
    if (f) {
        fprintf(f, "# Placeholder certificate for type=%s\n", type);
        fclose(f);
    }

    f = fopen(cert_info->key_path, "w");
    if (f) {
        fprintf(f, "# Placeholder private key for type=%s\n", type);
        fclose(f);
    }

    return 0;
}

int test_cert_load(test_cert_info_t *cert_info) {
    if (!cert_info) {
        return -1;
    }

    /* Check if files exist */
    if (access(cert_info->cert_path, R_OK) != 0) {
        return -1;
    }
    if (access(cert_info->key_path, R_OK) != 0) {
        return -1;
    }
    if (access(cert_info->ca_path, R_OK) != 0) {
        return -1;
    }

    if (cert_info->is_gm && cert_info->has_enc_cert) {
        if (access(cert_info->enc_cert_path, R_OK) != 0) {
            return -1;
        }
        if (access(cert_info->enc_key_path, R_OK) != 0) {
            return -1;
        }
    }

    return 0;
}

bool test_cert_is_valid(const test_cert_info_t *cert_info) {
    if (!cert_info) {
        return false;
    }

    time_t now = time(NULL);
    return (now >= cert_info->valid_from && now <= cert_info->valid_until);
}

void test_cert_cleanup(test_cert_info_t *cert_info) {
    if (!cert_info) {
        return;
    }

    /* Remove certificate files */
    unlink(cert_info->cert_path);
    unlink(cert_info->key_path);
    unlink(cert_info->ca_path);

    if (cert_info->is_gm && cert_info->has_enc_cert) {
        unlink(cert_info->enc_cert_path);
        unlink(cert_info->enc_key_path);
    }

    memset(cert_info, 0, sizeof(test_cert_info_t));
}

/* ============================================================================
 * File Utilities Implementation
 * ============================================================================ */

int test_file_create(const char *path, size_t size, bool random_content) {
    if (!path) {
        return -1;
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }

    if (random_content) {
        /* Generate random content */
        unsigned char buffer[8192];
        size_t remaining = size;

        while (remaining > 0) {
            size_t to_write = (remaining < sizeof(buffer)) ? remaining : sizeof(buffer);
            RAND_bytes(buffer, (int)to_write);
            fwrite(buffer, 1, to_write, f);
            remaining -= to_write;
        }
    } else {
        /* Fill with a pattern */
        unsigned char pattern[256];
        for (int i = 0; i < 256; i++) {
            pattern[i] = (unsigned char)i;
        }

        size_t remaining = size;
        while (remaining > 0) {
            size_t to_write = (remaining < sizeof(pattern)) ? remaining : sizeof(pattern);
            fwrite(pattern, 1, to_write, f);
            remaining -= to_write;
        }
    }

    fclose(f);
    return 0;
}

int test_file_md5(const char *path, char *md5_output) {
    if (!path || !md5_output) {
        return -1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    MD5_CTX ctx;
    MD5_Init(&ctx);

    unsigned char buffer[8192];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        MD5_Update(&ctx, buffer, bytes_read);
    }

    fclose(f);

    unsigned char md5_digest[MD5_DIGEST_LENGTH];
    MD5_Final(md5_digest, &ctx);

    /* Convert to hex string */
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(md5_output + (i * 2), "%02x", md5_digest[i]);
    }
    md5_output[MD5_DIGEST_LENGTH * 2] = '\0';

    return 0;
}

int test_file_compare(const char *path1, const char *path2) {
    if (!path1 || !path2) {
        return -2;
    }

    char md5_1[33], md5_2[33];

    if (test_file_md5(path1, md5_1) != 0) {
        return -2;
    }

    if (test_file_md5(path2, md5_2) != 0) {
        return -2;
    }

    return (strcmp(md5_1, md5_2) == 0) ? 0 : -1;
}

off_t test_file_size(const char *path) {
    if (!path) {
        return -1;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }

    return st.st_size;
}

int test_file_delete(const char *path) {
    if (!path) {
        return -1;
    }

    return unlink(path);
}

/* ============================================================================
 * SSL/TLS Test Utilities Implementation
 * ============================================================================ */

bool test_ssl_gm_support_available(void) {
    /* Check if GM algorithms are available in OpenSSL/Tongsuo */
    const EVP_MD *sm3 = EVP_sm3();
    const EVP_CIPHER *sm4 = EVP_sm4_cbc();

    return (sm3 != NULL && sm4 != NULL);
}

bool test_ssl_cipher_available(const char *cipher_suite) {
    if (!cipher_suite) {
        return false;
    }

    const SSL_METHOD *method = TLS_client_method();
    if (!method) {
        return false;
    }

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        return false;
    }

    /* Set cipher list and check if it was accepted */
    int ret = SSL_CTX_set_cipher_list(ctx, cipher_suite);

    SSL_CTX_free(ctx);

    return (ret == 1);
}

const char *test_ssl_default_gm_ciphers(void) {
    return "ECDHE-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-GCM-SM3";
}

bool test_ssl_mutual_auth_supported(void) {
    /* Mutual auth is supported in all modern OpenSSL versions */
    return true;
}

int test_ssl_validate_config(const void *options) {
    /* This would validate the obs_options structure */
    /* Implementation depends on the actual structure definition */
    (void)options;
    return 0;
}

/* ============================================================================
 * OBS Test Utilities Stub Implementation
 * ============================================================================ */

/* These are stubs that would need to be implemented based on actual OBS SDK */
/* The implementation would link against the actual OBS SDK library */

int test_obs_init_options(void *options) {
    (void)options;
    return 0;
}

int test_obs_config_standard_tls(void *options, const char *ca_path) {
    (void)options;
    (void)ca_path;
    return 0;
}

int test_obs_config_mutual_tls(void *options, const char *ca_path,
                               const char *client_cert, const char *client_key,
                               const char *password) {
    (void)options;
    (void)ca_path;
    (void)client_cert;
    (void)client_key;
    (void)password;
    return 0;
}

int test_obs_config_gm_mode(void *options, const char *ca_path) {
    (void)options;
    (void)ca_path;
    return 0;
}

int test_obs_config_gm_mutual(void *options, const char *ca_path,
                              const char *sign_cert, const char *sign_key,
                              const char *enc_cert, const char *enc_key) {
    (void)options;
    (void)ca_path;
    (void)sign_cert;
    (void)sign_key;
    (void)enc_cert;
    (void)enc_key;
    return 0;
}

void test_obs_cleanup_options(void *options) {
    (void)options;
}

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

int test_main(test_suite_t *suite) {
    if (!suite) {
        fprintf(stderr, "Error: No test suite provided\n");
        return 1;
    }

    int failed = test_suite_run(suite);
    test_suite_print_summary(suite);

    return failed;
}
