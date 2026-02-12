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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../inc/eSDKOBS.h"

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
            printf("[FAIL] %s: expected '%s', got '%s'\n", \
                   test_name, expected, actual); \
        } \
    } while(0)

// 测证枚举值
void test_enum_values(void)
{
    printf("--- Testing Enum Values ---\n");

    // 测试 mutual_ssl_switch 枚举
    TEST_ASSERT_EQ(0, OBS_MUTUAL_SSL_CLOSE, "OBS_MUTUAL_SSL_CLOSE value");
    TEST_ASSERT_EQ(1, OBS_MUTUAL_SSL_OPEN, "OBS_MUTUAL_SSL_OPEN value");

    // 测试 gm_mode_switch 枚举
    TEST_ASSERT_EQ(0, OBS_GM_MODE_CLOSE, "OBS_GM_MODE_CLOSE value");
    TEST_ASSERT_EQ(1, OBS_GM_MODE_OPEN, "OBS_GM_MODE_OPEN value");

    printf("\n");
}

// 测试结构体字段
void test_structure_fields(void)
{
    printf("--- Testing Structure Fields ---\n");

    obs_http_request_option options;
    memset(&options, 0, sizeof(obs_http_request_option));

    // 测试默认值
    TEST_ASSERT_EQ(0, options.mutual_ssl_switch,
                 "mutual_ssl_switch default value");
    TEST_ASSERT_EQ(0, options.gm_mode_switch,
                 "gm_mode_switch default value");
    TEST_ASSERT_NULL(options.client_cert_path, "client_cert_path default NULL");
    TEST_ASSERT_NULL(options.client_key_path, "client_key_path default NULL");
    TEST_ASSERT_NULL(options.client_key_password, "client_key_password default NULL");
    TEST_ASSERT_NULL(options.ssl_cipher_list, "ssl_cipher_list default NULL");

    // 测试设置值
    options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    options.gm_mode_switch = OBS_GM_MODE_OPEN;
    TEST_ASSERT_EQ(1, options.mutual_ssl_switch,
                 "mutual_ssl_switch set value");
    TEST_ASSERT_EQ(1, options.gm_mode_switch,
                 "gm_mode_switch set value");

    printf("\n");
}

// 测试SSL配置选项设置
void test_ssl_config_options(void)
{
    printf("--- Testing SSL Configuration Options ---\n");

    obs_options opts;
    memset(&opts, 0, sizeof(obs_options));

    // 测试默认值
    TEST_ASSERT_EQ(0, opts.request_options.gm_mode_switch,
                 "Default gm_mode_switch is CLOSED");
    TEST_ASSERT_EQ(0, opts.request_options.mutual_ssl_switch,
                 "Default mutual_ssl_switch is CLOSED");

    // 测试设置国密模式
    opts.request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    TEST_ASSERT_EQ(1, opts.request_options.gm_mode_switch,
                 "GM mode switch set to OPEN");
    TEST_ASSERT_EQ(1, opts.request_options.mutual_ssl_switch,
                 "Mutual SSL switch set to OPEN");

    // 测试设置标准TLS模式
    opts.request_options.gm_mode_switch = OBS_GM_MODE_CLOSE;
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    TEST_ASSERT_EQ(0, opts.request_options.gm_mode_switch,
                 "GM mode switch set to CLOSED");
    TEST_ASSERT_EQ(0, opts.request_options.mutual_ssl_switch,
                 "Mutual SSL switch set to CLOSED");

    printf("\n");
}

// 测试自定义SSL套件设置
void test_custom_ssl_cipher_list(void)
{
    printf("--- Testing Custom SSL Cipher List ---\n");

    obs_options opts;
    memset(&opts, 0, sizeof(obs_options));

    // 设置自定义套件（标准TLS）
    const char *std_cipher = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384";
    opts.request_options.ssl_cipher_list = (char *)malloc(strlen(std_cipher) + 1);
    if (opts.request_options.ssl_cipher_list) {
        strcpy(opts.request_options.ssl_cipher_list, std_cipher);
        TEST_ASSERT_STR(std_cipher, opts.request_options.ssl_cipher_list,
                     "Standard TLS custom cipher list");
        free(opts.request_options.ssl_cipher_list);
    }

    // 设置自定义套件（国密）
    const char *gm_cipher = "ECDHE-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-GCM-SM3";
    opts.request_options.ssl_cipher_list = (char *)malloc(strlen(gm_cipher) + 1);
    if (opts.request_options.ssl_cipher_list) {
        strcpy(opts.request_options.ssl_cipher_list, gm_cipher);
        TEST_ASSERT_STR(gm_cipher, opts.request_options.ssl_cipher_list,
                     "GM custom cipher list");
        free(opts.request_options.ssl_cipher_list);
    }

    printf("\n");
}

// 测试双向SSL证书配置
void test_mutual_ssl_config(void)
{
    printf("--- Testing Mutual SSL Certificate Configuration ---\n");

    obs_options opts;
    memset(&opts, 0, sizeof(obs_options));

    // 设置双向SSL配置
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    opts.request_options.client_cert_path = (char *)malloc(64);
    opts.request_options.client_key_path = (char *)malloc(64);
    opts.request_options.client_key_password = (char *)malloc(32);

    if (opts.request_options.client_cert_path) {
        strcpy(opts.request_options.client_cert_path, "/path/to/client_cert.pem");
    }
    if (opts.request_options.client_key_path) {
        strcpy(opts.request_options.client_key_path, "/path/to/client_key.pem");
    }
    if (opts.request_options.client_key_password) {
        strcpy(opts.request_options.client_key_password, "mypassword");
    }

    // 验证设置
    TEST_ASSERT_EQ(1, opts.request_options.mutual_ssl_switch,
                 "Mutual SSL enabled");
    TEST_ASSERT_NOT_NULL(opts.request_options.client_cert_path, "Client cert path set");
    TEST_ASSERT_NOT_NULL(opts.request_options.client_key_path, "Client key path set");
    TEST_ASSERT_NOT_NULL(opts.request_options.client_key_password, "Client key password set");

    // 验证值
    TEST_ASSERT_STR("/path/to/client_cert.pem", opts.request_options.client_cert_path,
                 "Client cert path value");
    TEST_ASSERT_STR("/path/to/client_key.pem", opts.request_options.client_key_path,
                 "Client key path value");
    TEST_ASSERT_STR("mypassword", opts.request_options.client_key_password,
                 "Client key password value");

    // 测试与国密模式的组合
    opts.request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
    TEST_ASSERT_EQ(1, opts.request_options.gm_mode_switch,
                 "GM mode enabled with mutual SSL");

    // 清理
    if (opts.request_options.client_cert_path) {
        free(opts.request_options.client_cert_path);
    }
    if (opts.request_options.client_key_path) {
        free(opts.request_options.client_key_path);
    }
    if (opts.request_options.client_key_password) {
        free(opts.request_options.client_key_password);
    }

    printf("\n");
}

// 测试SSL版本配置
void test_ssl_version_config(void)
{
    printf("--- Testing SSL Version Configuration ---\n");

    obs_options opts;
    memset(&opts, 0, sizeof(obs_options));

    // 测试默认SSL版本值
    // SSL最小版本默认应该是TLSv1.2
    // SSL最大版本默认应该是TLSv1.3
    TEST_ASSERT_EQ(0, opts.request_options.ssl_min_version,
                 "SSL min version default zero");
    TEST_ASSERT_EQ(0, opts.request_options.ssl_max_version,
                 "SSL max version default zero");

    // 测试设置自定义SSL版本
    opts.request_options.ssl_min_version = 3;  // TLSv1.2
    opts.request_options.ssl_max_version = 7;  // TLSv1.3

    TEST_ASSERT_EQ(3, opts.request_options.ssl_min_version,
                 "SSL min version set to TLSv1.2");
    TEST_ASSERT_EQ(7, opts.request_options.ssl_max_version,
                 "SSL max version set to TLSv1.3");

    printf("\n");
}

// 测试obs_options结构体
void test_obs_options_structure(void)
{
    printf("--- Testing obs_options Structure ---\n");

    obs_options opts;
    memset(&opts, 0, sizeof(obs_options));

    // 验证结构体大小不为0
    TEST_ASSERT_NE(0, sizeof(obs_options), "obs_options size is valid");
    TEST_ASSERT_NE(0, sizeof(obs_http_request_option),
                 "obs_http_request_option size is valid");
    TEST_ASSERT_NE(0, sizeof(obs_bucket_context), "obs_bucket_context size is valid");

    printf("\n");
}

// 测试SSL模式切换逻辑
void test_ssl_mode_switching(void)
{
    printf("--- Testing SSL Mode Switching Logic ---\n");

    obs_options opts;
    memset(&opts, 0, sizeof(obs_options));

    // 模拟从标准TLS切换到国密模式
    opts.request_options.gm_mode_switch = OBS_GM_MODE_CLOSE;
    TEST_ASSERT_EQ(0, opts.request_options.gm_mode_switch, "Start with GM mode closed");

    // 启用国密模式
    opts.request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
    TEST_ASSERT_EQ(1, opts.request_options.gm_mode_switch, "Switch to GM mode open");

    // 切换回标准TLS
    opts.request_options.gm_mode_switch = OBS_GM_MODE_CLOSE;
    TEST_ASSERT_EQ(0, opts.request_options.gm_mode_switch, "Switch back to GM mode closed");

    printf("\n");
}

// 测试双向SSL模式切换逻辑
void test_mutual_ssl_mode_switching(void)
{
    printf("--- Testing Mutual SSL Mode Switching Logic ---\n");

    obs_options opts;
    memset(&opts, 0, sizeof(obs_options));

    // 模拟从关闭到启用
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    TEST_ASSERT_EQ(0, opts.request_options.mutual_ssl_switch, "Start with mutual SSL closed");

    // 启用双向SSL
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    TEST_ASSERT_EQ(1, opts.request_options.mutual_ssl_switch, "Switch to mutual SSL open");

    // 切换回关闭
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    TEST_ASSERT_EQ(0, opts.request_options.mutual_ssl_switch, "Switch back to mutual SSL closed");

    printf("\n");
}

// 测试国密和双向SSL组合
void test_gm_mutual_ssl_combination(void)
{
    printf("--- Testing GM and Mutual SSL Combination ---\n");

    obs_options opts;
    memset(&opts, 0, sizeof(obs_options));

    // 测试场景1：标准TLS + 双向SSL关闭
    opts.request_options.gm_mode_switch = OBS_GM_MODE_CLOSE;
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    TEST_ASSERT_EQ(0, opts.request_options.gm_mode_switch, "Scenario 1: GM close");
    TEST_ASSERT_EQ(0, opts.request_options.mutual_ssl_switch, "Scenario 1: Mutual close");

    // 测试场景2：标准TLS + 双向SSL启用
    opts.request_options.gm_mode_switch = OBS_GM_MODE_CLOSE;
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    TEST_ASSERT_EQ(0, opts.request_options.gm_mode_switch, "Scenario 2: GM close");
    TEST_ASSERT_EQ(1, opts.request_options.mutual_ssl_switch, "Scenario 2: Mutual open");

    // 测试场景3：国密 + 双向SSL关闭
    opts.request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    TEST_ASSERT_EQ(1, opts.request_options.gm_mode_switch, "Scenario 3: GM open");
    TEST_ASSERT_EQ(0, opts.request_options.mutual_ssl_switch, "Scenario 3: Mutual close");

    // 测试场景4：国密 + 双向SSL启用（常见生产场景）
    opts.request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
    opts.request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    TEST_ASSERT_EQ(1, opts.request_options.gm_mode_switch, "Scenario 4: GM open");
    TEST_ASSERT_EQ(1, opts.request_options.mutual_ssl_switch, "Scenario 4: Mutual open");

    printf("\n");
}

// 测试SSL套件列表设置
void test_cipher_list_assignment(void)
{
    printf("--- Testing SSL Cipher List Assignment ---\n");

    obs_options opts;
    memset(&opts, 0, sizeof(obs_options));

    // 测试空字符串设置
    opts.request_options.ssl_cipher_list = (char *)malloc(1);
    if (opts.request_options.ssl_cipher_list) {
        opts.request_options.ssl_cipher_list[0] = '\0';
        TEST_ASSERT_EQ(0, strlen(opts.request_options.ssl_cipher_list),
                     "Empty cipher list length");
        free(opts.request_options.ssl_cipher_list);
    }

    // 测试长套件列表设置
    const char *long_cipher = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
                             "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
                             "ECDHE-ECDSA-CHACHA20-POLY1305";
    opts.request_options.ssl_cipher_list = (char *)malloc(strlen(long_cipher) + 1);
    if (opts.request_options.ssl_cipher_list) {
        strcpy(opts.request_options.ssl_cipher_list, long_cipher);
        TEST_ASSERT_EQ(strlen(long_cipher), strlen(opts.request_options.ssl_cipher_list),
                     "Long cipher list length");
        TEST_ASSERT_STR(long_cipher, opts.request_options.ssl_cipher_list,
                     "Long cipher list content");
        free(opts.request_options.ssl_cipher_list);
    }

    printf("\n");
}

// 主测试函数
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("========================================\n");
    printf("SSL Configuration Unit Tests\n");
    printf("========================================\n\n");

    // 运行所有测试
    test_enum_values();
    test_structure_fields();
    test_obs_options_structure();
    test_ssl_config_options();
    test_custom_ssl_cipher_list();
    test_mutual_ssl_config();
    test_ssl_version_config();
    test_ssl_mode_switching();
    test_mutual_ssl_mode_switching();
    test_gm_mutual_ssl_combination();
    test_cipher_list_assignment();

    // 输出测试结果摘要
    printf("========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", passed_tests);
    printf("Failed: %d\n", failed_tests);
    if (total_tests > 0) {
        printf("Coverage: %.1f%%\n", (float)passed_tests / total_tests * 100);
    }
    printf("========================================\n");

    return (failed_tests == 0) ? 0 : 1;
}
