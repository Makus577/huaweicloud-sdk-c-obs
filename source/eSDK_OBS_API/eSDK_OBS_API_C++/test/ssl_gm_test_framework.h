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
 * @file ssl_gm_test_framework.h
 * @brief Test framework for SSL/TLS and GM (National Cryptography) tests
 *
 * This framework provides utilities for testing SSL configuration,
 * mutual authentication, and national cryptography features.
 */

#ifndef SSL_GM_TEST_FRAMEWORK_H
#define SSL_GM_TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants and Macros
 * ============================================================================ */

/** Maximum number of test cases */
#define MAX_TEST_CASES 256

/** Maximum length of test names */
#define MAX_TEST_NAME_LEN 128

/** Maximum length of error messages */
#define MAX_ERROR_MSG_LEN 512

/** Maximum number of assertions per test */
#define MAX_ASSERTIONS 1024

/** Default certificate file path (for testing) */
#define DEFAULT_CERT_DIR "/tmp/ssl_test_certs"

/** Test file size for breakpoint resume tests (50MB) */
#define TEST_FILE_SIZE (50 * 1024 * 1024)

/** Segment size for multipart upload (5MB) */
#define SEGMENT_SIZE (5 * 1024 * 1024)

/** Number of concurrent segments */
#define CONCURRENT_SEGMENTS 3

/* ============================================================================
 * Type Definitions
 * ============================================================================ */

/** Test result status */
typedef enum {
    TEST_NOT_RUN = 0,       /**< Test has not been run */
    TEST_PASSED,            /**< Test passed */
    TEST_FAILED,            /**< Test failed */
    TEST_SKIPPED,           /**< Test was skipped */
    TEST_ERROR              /**< Test encountered an error */
} test_result_t;

/** Test case structure */
typedef struct test_case {
    char name[MAX_TEST_NAME_LEN];   /**< Test name */
    char description[256];          /**< Test description */
    void (*test_func)(struct test_case *tc);  /**< Test function */
    test_result_t result;           /**< Test result */
    int assertions_total;         /**< Total assertions */
    int assertions_passed;          /**< Passed assertions */
    int assertions_failed;          /**< Failed assertions */
    char error_msg[MAX_ERROR_MSG_LEN];  /**< Error message */
    double execution_time;          /**< Execution time in seconds */
    void *user_data;                /**< User data pointer */
} test_case_t;

/** Test suite structure */
typedef struct test_suite {
    char name[MAX_TEST_NAME_LEN];   /**< Suite name */
    char description[256];          /**< Suite description */
    test_case_t *tests[MAX_TEST_CASES];  /**< Test cases */
    int test_count;                 /**< Number of tests */
    int tests_passed;               /**< Number of passed tests */
    int tests_failed;               /**< Number of failed tests */
    int tests_skipped;              /**< Number of skipped tests */
    double total_execution_time;    /**< Total execution time */
    void (*setup)(void);            /**< Setup function */
    void (*teardown)(void);         /**< Teardown function */
} test_suite_t;

/** Test certificate information */
typedef struct {
    char cert_path[256];            /**< Certificate file path */
    char key_path[256];             /**< Private key file path */
    char enc_cert_path[256];        /**< Encryption certificate path (GM only) */
    char enc_key_path[256];         /**< Encryption key path (GM only) */
    char ca_path[256];              /**< CA certificate path */
    bool is_gm;                     /**< Whether this is a GM certificate */
    bool has_enc_cert;              /**< Whether encryption cert is available */
    time_t valid_from;              /**< Valid from time */
    time_t valid_until;             /**< Valid until time */
} test_cert_info_t;

/** Test configuration */
typedef struct {
    char test_dir[256];             /**< Test directory */
    char cert_dir[256];             /**< Certificate directory */
    char temp_dir[256];             /**< Temporary files directory */
    bool verbose;                   /**< Verbose output */
    bool generate_certs;            /**< Auto-generate certificates */
    int test_timeout;               /**< Test timeout in seconds */
    char obs_endpoint[256];         /**< OBS endpoint */
    char obs_bucket[256];           /**< OBS test bucket */
} test_config_t;

/* ============================================================================
 * Global Variables
 * ============================================================================ */

extern test_config_t g_test_config;
extern test_suite_t *g_current_suite;
extern test_case_t *g_current_test;

/* ============================================================================
 * Function Declarations - Test Framework Core
 * ============================================================================ */

/**
 * @brief Initialize the test framework
 * @param config Test configuration (can be NULL for defaults)
 * @return 0 on success, -1 on failure
 */
int test_framework_init(test_config_t *config);

/**
 * @brief Cleanup the test framework
 */
void test_framework_cleanup(void);

/**
 * @brief Create a new test suite
 * @param name Suite name
 * @param description Suite description
 * @return Pointer to created suite, NULL on failure
 */
test_suite_t *test_suite_create(const char *name, const char *description);

/**
 * @brief Destroy a test suite
 * @param suite Suite to destroy
 */
void test_suite_destroy(test_suite_t *suite);

/**
 * @brief Register a test case with a suite
 * @param suite Test suite
 * @param name Test name
 * @param description Test description
 * @param test_func Test function
 * @return 0 on success, -1 on failure
 */
int test_suite_add_test(test_suite_t *suite, const char *name,
                        const char *description,
                        void (*test_func)(test_case_t *tc));

/**
 * @brief Run all tests in a suite
 * @param suite Test suite
 * @return Number of tests that passed
 */
int test_suite_run(test_suite_t *suite);

/**
 * @brief Print test suite summary
 * @param suite Test suite
 */
void test_suite_print_summary(const test_suite_t *suite);

/* ============================================================================
 * Function Declarations - Assertions
 * ============================================================================ */

/**
 * @brief Record a test assertion
 * @param condition Condition to check
 * @param file Source file
 * @param line Line number
 * @param fmt Format string
 * @param ... Variable arguments
 */
void test_assert_impl(bool condition, const char *file, int line,
                      const char *fmt, ...);

/**
 * @brief Record a test assertion for string equality
 * @param expected Expected string
 * @param actual Actual string
 * @param file Source file
 * @param line Line number
 */
void test_assert_str_eq_impl(const char *expected, const char *actual,
                             const char *file, int line);

/**
 * @brief Record a test assertion for integer equality
 * @param expected Expected value
 * @param actual Actual value
 * @param file Source file
 * @param line Line number
 */
void test_assert_int_eq_impl(long expected, long actual,
                            const char *file, int line);

/** Test assertion macros */
#define TEST_ASSERT(cond) \
    test_assert_impl((cond), __FILE__, __LINE__, "%s", #cond)

#define TEST_ASSERT_MSG(cond, ...) \
    test_assert_impl((cond), __FILE__, __LINE__, __VA_ARGS__)

#define TEST_ASSERT_STR_EQ(expected, actual) \
    test_assert_str_eq_impl((expected), (actual), __FILE__, __LINE__)

#define TEST_ASSERT_INT_EQ(expected, actual) \
    test_assert_int_eq_impl((expected), (actual), __FILE__, __LINE__)

#define TEST_ASSERT_NULL(ptr) \
    test_assert_impl((ptr) == NULL, __FILE__, __LINE__, \
                     "Expected NULL, got %p", (ptr))

#define TEST_ASSERT_NOT_NULL(ptr) \
    test_assert_impl((ptr) != NULL, __FILE__, __LINE__, \
                     "Expected non-NULL, got NULL")

#define TEST_FAIL(msg) \
    test_assert_impl(false, __FILE__, __LINE__, "Test failed: %s", (msg))

#define TEST_SKIP(msg) \
    do { \
        if (g_current_test) { \
            g_current_test->result = TEST_SKIPPED; \
            snprintf(g_current_test->error_msg, MAX_ERROR_MSG_LEN, \
                     "Skipped: %s", (msg)); \
        } \
        return; \
    } while(0)

/* ============================================================================
 * Function Declarations - Certificate Utilities
 * ============================================================================ */

/**
 * @brief Generate a test certificate
 * @param cert_info Certificate information structure
 * @param type Certificate type ("rsa", "ecdsa", "sm2")
 * @param valid_days Validity period in days
 * @return 0 on success, -1 on failure
 */
int test_cert_generate(test_cert_info_t *cert_info, const char *type,
                       int valid_days);

/**
 * @brief Load a certificate from file
 * @param cert_info Certificate information structure
 * @return 0 on success, -1 on failure
 */
int test_cert_load(test_cert_info_t *cert_info);

/**
 * @brief Check if a certificate is valid
 * @param cert_info Certificate information
 * @return true if valid, false otherwise
 */
bool test_cert_is_valid(const test_cert_info_t *cert_info);

/**
 * @brief Clean up certificate resources
 * @param cert_info Certificate information
 */
void test_cert_cleanup(test_cert_info_t *cert_info);

/**
 * @brief Create test certificate directory
 * @return 0 on success, -1 on failure
 */
int test_cert_init_directory(void);

/**
 * @brief Clean up test certificate directory
 */
void test_cert_cleanup_directory(void);

/* ============================================================================
 * Function Declarations - Test File Utilities
 * ============================================================================ */

/**
 * @brief Create a test file with specified size
 * @param path File path
 * @param size File size in bytes
 * @param random_content Fill with random content if true
 * @return 0 on success, -1 on failure
 */
int test_file_create(const char *path, size_t size, bool random_content);

/**
 * @brief Calculate MD5 checksum of a file
 * @param path File path
 * @param md5_output Output buffer (at least 33 bytes for hex string)
 * @return 0 on success, -1 on failure
 */
int test_file_md5(const char *path, char *md5_output);

/**
 * @brief Compare two files
 * @param path1 First file path
 * @param path2 Second file path
 * @return 0 if equal, -1 if different, -2 on error
 */
int test_file_compare(const char *path1, const char *path2);

/**
 * @brief Get file size
 * @param path File path
 * @return File size in bytes, or -1 on error
 */
off_t test_file_size(const char *path);

/**
 * @brief Delete a file
 * @param path File path
 * @return 0 on success, -1 on failure
 */
int test_file_delete(const char *path);

/* ============================================================================
 * Function Declarations - SSL/TLS Test Utilities
 * ============================================================================ */

/**
 * @brief Check if GM (National Cryptography) support is available
 * @return true if GM support is available, false otherwise
 */
bool test_ssl_gm_support_available(void);

/**
 * @brief Check if a specific cipher suite is available
 * @param cipher_suite Cipher suite name
 * @return true if available, false otherwise
 */
bool test_ssl_cipher_available(const char *cipher_suite);

/**
 * @brief Get default GM cipher list
 * @return Default GM cipher list string
 */
const char *test_ssl_default_gm_ciphers(void);

/**
 * @brief Check if mutual SSL is supported
 * @return true if supported, false otherwise
 */
bool test_ssl_mutual_auth_supported(void);

/**
 * @brief Validate SSL configuration
 * @param options obs_options pointer
 * @return 0 if valid, -1 if invalid
 */
int test_ssl_validate_config(const void *options);

/* ============================================================================
 * Function Declarations - OBS Test Utilities
 * ============================================================================ */

/**
 * @brief Initialize OBS options for testing
 * @param options Pointer to obs_options structure
 * @return 0 on success, -1 on failure
 */
int test_obs_init_options(void *options);

/**
 * @brief Configure OBS options for standard TLS
 * @param options Pointer to obs_options structure
 * @param ca_path CA certificate path
 * @return 0 on success, -1 on failure
 */
int test_obs_config_standard_tls(void *options, const char *ca_path);

/**
 * @brief Configure OBS options for mutual TLS
 * @param options Pointer to obs_options structure
 * @param ca_path CA certificate path
 * @param client_cert Client certificate path
 * @param client_key Client private key path
 * @param password Private key password (can be NULL)
 * @return 0 on success, -1 on failure
 */
int test_obs_config_mutual_tls(void *options, const char *ca_path,
                               const char *client_cert, const char *client_key,
                               const char *password);

/**
 * @brief Configure OBS options for GM mode
 * @param options Pointer to obs_options structure
 * @param ca_path CA certificate path
 * @return 0 on success, -1 on failure
 */
int test_obs_config_gm_mode(void *options, const char *ca_path);

/**
 * @brief Configure OBS options for GM mutual auth
 * @param options Pointer to obs_options structure
 * @param ca_path CA certificate path
 * @param sign_cert Signing certificate path
 * @param sign_key Signing key path
 * @param enc_cert Encryption certificate path
 * @param enc_key Encryption key path
 * @return 0 on success, -1 on failure
 */
int test_obs_config_gm_mutual(void *options, const char *ca_path,
                              const char *sign_cert, const char *sign_key,
                              const char *enc_cert, const char *enc_key);

/**
 * @brief Cleanup OBS options
 * @param options Pointer to obs_options structure
 */
void test_obs_cleanup_options(void *options);

/* ============================================================================
 * Logging and Reporting
 * ============================================================================ */

/**
 * @brief Set verbose mode for logging
 * @param verbose true to enable verbose output
 */
void test_set_verbose(bool verbose);

/**
 * @brief Log a message
 * @param level Log level (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)
 * @param fmt Format string
 * @param ... Variable arguments
 */
void test_log(int level, const char *fmt, ...);

/**
 * @brief Print colored text to stdout
 * @param color Color code (0=default, 1=red, 2=green, 3=yellow, 4=blue)
 * @param fmt Format string
 * @param ... Variable arguments
 */
void test_print_color(int color, const char *fmt, ...);

/* ============================================================================
 * Main Entry Point
 * ============================================================================ */

/**
 * @brief Main entry point for running a test suite
 * @param suite Test suite to run
 * @return Number of failed tests
 */
int test_main(test_suite_t *suite);

#ifdef __cplusplus
}
#endif

#endif /* SSL_GM_TEST_FRAMEWORK_H */
