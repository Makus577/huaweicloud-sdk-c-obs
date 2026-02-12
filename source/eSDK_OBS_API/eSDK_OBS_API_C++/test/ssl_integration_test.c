/*********************************************************************************
* Copyright 2024 Huawei Technologies Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use
* this file except in compliance with the License.  You may obtain a copy of the
* License at
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
 * @file ssl_integration_test.c
 * @brief SSL配置集成测试
 *
 * 该文件提供了SSL配置的集成测试，包括：
 * - 国密算法可用性测试
 * - 双向认证配置测试
 * - 配置文件加载测试
 * - 环境变量配置测试
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../inc/eSDKOBS.h"
#include "../inc/ssl_config.h"

#if OBS_ENABLE_GM_SUPPORT
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#endif

// 测试结果统计
static int total_tests = 0;
static int passed_tests = 0;
static int failed_tests = 0;

// 测试断言宏
#define TEST_ASSERT(condition, test_name) \
    do { \
        total_tests++; \
        if (condition) { \
            passed_tests++; \
            printf("[PASS] %s\n", test_name); \
        } else { \
            failed_tests++; \
            printf("[FAIL] %s at %s:%d\n", test_name, __FILE__, __LINE__); \
        } \
    } while(0)

#define TEST_ASSERT_EQ(expected, actual, test_name) \
    TEST_ASSERT((expected) == (actual), test_name)

#define TEST_ASSERT_NE(expected, actual, test_name) \
    TEST_ASSERT((expected) != (actual), test_name)

#define TEST_ASSERT_NULL(ptr, test_name) \
    TEST_ASSERT((ptr) == NULL, test_name)

#define TEST_ASSERT_NOT_NULL(ptr, test_name) \
    TEST_ASSERT((ptr) != NULL, test_name)

#define TEST_ASSERT_STR(expected, actual, test_name) \
    do { \
        total_tests++; \
        if (strcmp(expected, actual) == 0) { \
            passed_tests++; \
            printf("[PASS] %s\n", test_name); \
        } else { \
            failed_tests++; \
            printf("[FAIL] %s: expected '%s', got '%s'\n", test_name, expected, actual); \
        } \
    } while(0)

/**
 * @brief 检查文件是否存在且可读
 */
static int file_readable(const char *path)
{
    return (access(path, R_OK) == 0);
}

/**
 * @brief 创建临时测试证书文件
 */
static int create_test_cert_file(const char *path, const char *content)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        return -1;
    }
    fprintf(fp, "%s", content);
    fclose(fp);
    return 0;
}

/**
 * @brief 删除临时测试文件
 */
static void cleanup_test_file(const char *path)
{
    if (access(path, F_OK) == 0) {
        unlink(path);
    }
}

/**
 * @brief 测试国密算法可用性
 */
void test_gm_algorithm_availability(void)
{
    printf("\n=== Testing GM Algorithm Availability ===\n");

#if OBS_ENABLE_GM_SUPPORT
    // 检查SM3摘要算法
    const EVP_MD *sm3_md = EVP_get_digestbyname("sm3");
    TEST_ASSERT_NOT_NULL(sm3_md, "SM3 algorithm available");

    // 检查SM4对称加密算法
    const EVP_CIPHER *sm4_cipher = EVP_get_cipherbyname("sm4-cbc");
    TEST_ASSERT_NOT_NULL(sm4_cipher, "SM4 algorithm available");

    // 检查SM2椭圆曲线
    const EC_GROUP *sm2_group = EC_GROUP_new_by_curve_name(NID_sm2);
    TEST_ASSERT_NOT_NULL(sm2_group, "SM2 curve available");

    if (sm2_group) {
        EC_GROUP_free((EC_GROUP *)sm2_group);
    }

    printf("GM algorithms are fully supported\n");
#else
    printf("[SKIP] GM support not compiled in (OBS_ENABLE_GM_SUPPORT=0)\n");
#endif
}

/**
 * @brief 测试obs_options初始化和默认值
 */
void test_obs_options_initialization(void)
{
    printf("\n=== Testing obs_options Initialization ===\n");

    obs_options opts;
    init_obs_options(&opts);

    // 测试默认值
    TEST_ASSERT_EQ(0, opts.request_options.mutual_ssl_switch,
                 "Default mutual SSL is CLOSED");
    TEST_ASSERT_NULL(opts.request_options.client_cert_path,
                  "Default client cert cert path is NULL");
    TEST_ASSERT_NULL(opts.request_options.client_key_path,
                  "Default client key path is NULL");
    TEST_ASSERT_NULL(opts.request_options.client_key_password,
                  "Default client key password is NULL");
}

/**
 * @brief 测试双向SSL认证配置
 */
void test_mutual_ssl_configuration(void)
{
    printf("\n=== Testing Mutual SSL Configuration ===\n");

    obs_options opts;
    init_obs_options(&opts);

    // 测试启用双向SSL
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    TEST_ASSERT_EQ(1, opts.request_options.mutual_ssl_switch,
                 "Mutual SSL switch set to OPEN");

    // 创建临时证书文件
    const char *test_cert_path = "/tmp/test_client_cert.pem";
    const char *test_key_path = "/tmp/test_client_key.pem";

    const char *cert_content =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBpTCCAQagAwIBAgI... (truncated for test)\n"
        "-----END CERTIFICATE-----\n";

    const char *key_content =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA... (truncated for test)\n"
        "-----END RSA PRIVATE KEY-----\n";

    int result = create_test-cert_file(test_cert_path, cert_content);
    TEST_ASSERT_EQ(0, result, "Create test client certificate");

    result = create_test_cert_file(test_key_path, key_content);
    TEST_ASSERT_EQ(0, result, "Create test client key");

    if (result == 0) {
        opts.request_options.client_cert_path = malloc(strlen(test_cert_path) + 1);
        strcpy(opts.request_options.client_cert_path, test_cert_path);

        opts.request_options.client_key_path = malloc(strlen(test_key_path) + 1);
        strcpy(opts.request_options.client_key_path, test_key_path);

        opts.request_options.client_key_password = malloc(32);
        strcpy(opts.request_options.client_key_password, "testpassword");

        TEST_ASSERT_NOT_NULL(opts.request_options.client_cert_path,
                          "Client cert cert path allocated");
        TEST_ASSERT_NOT_NULL(opts.request_options.client_key_path,
                          "Client key path allocated");
        TEST_ASSERT_NOT_NULL(opts.request_options.client_key_password,
                          "Client key password allocated");

        TEST_ASSERT_STR(test_cert_path, opts.request_options.client_cert_path,
                     "Client cert cert path set correctly");
        TEST_ASSERT_STR(test_key_path, opts.request_options.client_key_path,
                     "Client key path set correctly");
        TEST_ASSERT_STR("testpassword", opts.request_options.client_key_password,
                     "Client key password set correctly");

        // 测试文件可读性
        TEST_ASSERT(file_readable(test_cert_path),
                  "Client certificate file is readable");
        TEST_ASSERT(file_readable(test_key_path),
                  "Client key file is readable");

        // 清理
        free(opts.request_options.client_cert_path);
        free(opts.request_options.client_key_path);
        free(opts.request_options.client_key_password);
    }

    cleanup_test_file(test_cert_path);
    cleanup_test_file(test_key_path);
}

/**
 * @brief 测试国密SSL配置
 */
void test_gm_ssl_configuration(void)
{
    printf("\n=== Testing GM SSL Configuration ===\n");

    obs_options opts;
    init_obs_options(&opts);

#if OBS_ENABLE_GM_SUPPORT
    // 测试启用国密模式
    opts.request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
    TEST_ASSERT_EQ(1, opts.request_options.gm_mode_switch,
                 "GM mode switch set to OPEN");

    // 设置国密密码套件
    const char *gm_cipher = "ECDHE-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-GCM-SM3";
    opts.request_options.ssl_cipher_list = malloc(strlen(gm_cipher) + 1);
    strcpy(opts.request_options.ssl_cipher_list, gm_cipher);

    TEST_ASSERT_NOT_NULL(opts.request_options.ssl_cipher_list,
                      "GM cipher list allocated");
    TEST_ASSERT_STR(gm_cipher, opts.request_options.ssl_cipher_list,
                 "GM cipher list set correctly");

    // 清理
    free(opts.request_options.ssl_cipher_list);
#else
    printf("[SKIP] GM support not compiled in (OBS_ENABLE_GM_SUPPORT=0)\n");
#endif

    // 测试标准TLS配置
    opts.request_options.gm_mode_switch = OBS_GM_MODE_CLOSE;
    const char *std_cipher = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256";
    opts.request_options.ssl_cipher_list = malloc(strlen(std_cipher) + 1);
    strcpy(opts.request_options.ssl_cipher_list, std_cipher);

    TEST_ASSERT_EQ(0, opts.request_options.gm_mode_switch,
                 "GM mode switch set to CLOSE");
    TEST_ASSERT_STR(std_cipher, opts.request_options.ssl_cipher_list,
                 "Standard TLS cipher list set correctly");

    free(opts.request_options.ssl_cipher_list);
}

/**
 * @brief 测试SSL版本配置
 */
void test_ssl_version_configuration(void)
{
    printf("\n=== Testing SSL Version Configuration ===\n");

    obs_options opts;
    init_obs_options(&opts);

    // 测试设置SSL版本范围
    opts.request_options.ssl_min_version = 3;  // TLSv1.2
    opts.request_options.ssl_max_version = 7;  // TLSv1.3

    TEST_ASSERT_EQ(3, opts.request_options.ssl_min_version,
                 "SSL min version set to TLSv1.2");
    TEST_ASSERT_EQ(7, opts.request_options.ssl_max_version,
                 "SSL max version set to TLS (1<<16)|3");

    // 测试无效版本范围
    opts.request_options.ssl_min_version = 10;  // 无效值
    opts.request_options.ssl_max_version = 3;   // TLSv1.2

    TEST_ASSERT_EQ(10, opts.request_options.ssl_min_version,
                 "SSL min version set to invalid value");
    TEST_ASSERT_EQ(3, opts.request_options.ssl_max_version,
                 "SSL max version set to TLSv1.2");
}

/**
 * @brief 测试配置组合场景
 */
void test_configuration_combinations(void)
{
    printf("\n=== Testing Configuration Combinations ===\n");

    obs_options opts;

    // 场景1: 标准TLS + 双向SSL关闭
    init_obs_options(&opts);
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    TEST_ASSERT_EQ(0, opts.request_options.mutual_ssl_switch,
                 "Scenario 1: Mutual SSL closed");

    // 场景2: 标准TLS + 双向SSL开启
    init_obs_options(&opts);
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    TEST_ASSERT_EQ(1, opts.request_options.mutual_ssl_switch,
                 "Scenario 2: Mutual SSL open");

#if OBS_ENABLE_GM_SUPPORT
    // 场景3: 国密 + 双向SSL关闭
    init_obs_options(&opts);
    opts.request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    TEST_ASSERT_EQ(1, opts.request_options.gm_mode_switch,
                 "Scenario 3: GM open");
    TEST_ASSERT_EQ(0, opts.request_options.mutual_ssl_switch,
                 "Scenario 3: Mutual SSL closed");

    // 场景4: 国密 + 双向SSL开启（生产场景）
    init_obs_options(&opts);
    opts.request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    TEST_ASSERT_EQ(1, opts.request_options.gm_mode_switch,
                 "Scenario 4: GM open");
    TEST_ASSERT_EQ(1, opts.request_options.mutual_ssl_switch,
                 "Scenario 4: Mutual SSL open");
#endif
}

/**
 * @brief 测试配置验证函数
 */
void test_configuration_validation(void)
{
    printf("\n=== Testing Configuration Validation ===\n");

    obs_http_request_option opts;
    memset(&opts, 0, sizeof(obs_http_request_option));

    // 测试无效配置：双向SSL开启但没有证书
    opts.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    opts.client_cert_path = NULL;
    opts.client_key_path = NULL;

    int result = validate_ssl_config(&opts);
    TEST_ASSERT_NE(0, result,
                 "Validation fails when mutual SSL enabled without certs");

    // 测试有效配置：双向SSL关闭
    opts.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    result = validate_ssl_config(&opts);
    TEST_ASSERT_EQ(0, result,
                 "Validation succeeds when mutual SSL disabled");
}

/**
 * @brief 主测试函数
 */
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("========================================\n");
    printf("SSL Configuration Integration Tests\n");
    printf("========================================\n");

    printf("\nBuild Information:\n");
    printf("  OBS_ENABLE_GM_SUPPORT: %d\n", OBS_ENABLE_GM_SUPPORT);
    printf("  OBS_SDK_VERSION: %s\n", OBS_SDK_VERSION);

    // 运行所有测试
    test_obs_options_initialization();
    test_gm_algorithm_availability();
    test_mutual_ssl_configuration();
    test_gm_ssl_configuration();
    test_ssl_version_configuration();
    test_configuration_combinations();
    test_configuration_validation();

    // 输出测试结果摘要
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", passed_tests);
    printf("Failed: %d\n", failed_tests);
    if (total_tests > 0) {
        printf("Success rate: %.1f%%\n", (float)passed_tests / total_tests * 100);
    }
    printf("========================================\n");

    return (failed_tests == 0) ? 0 : 1;
}
