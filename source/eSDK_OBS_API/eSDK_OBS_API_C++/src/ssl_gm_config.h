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
**********************************************************************************/
/**
 * @file ssl_gm_config.h
 * @brief 国密SSL配置接口
 *
 * 该模块提供国密SSL配置相关功能的接口，包括国密算法检测、
 * 国密证书验证等。该模块仅在OBS_ENABLE_GM_SUPPORT=1时编译。
 */

#ifndef SSL_GM_CONFIG_H
#define SSL_GM_CONFIG_H

#include "eSDKOBS.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 国密SSL配置初始化
 *
 * 检查国密算法是否可用。
 * 注意：Tongsuo在SSL_library_init()时已自动注册SM算法，这里仅验证可用性。
 *
 * @return int 初始化结果：0表示成功，负数表示失败
 *         -1: SM3算法不可用
 *         -2: SM4-GCM算法不可用
 *         -3: SM4-CBC算法不可用
 *         -4: SM2曲线不可用
 */
int obs_ssl_gm_config_init(void);

/**
 * @brief 国密密码套件配置
 *
 * 配置SSL上下文的国密密码套件。
 *
 * @param ssl_ctx SSL上下文
 * @param cipher_list 密码套件列表
 * @return int 配置结果：0表示成功，负数表示失败
 */
int obs_ssl_gm_configure_ciphers(SSL_CTX *ssl_ctx, const char *cipher_list);

/**
 * @brief 国密证书验证配置
 *
 * 配置SSL上下文的国密证书验证方法。
 *
 * @param ssl_ctx SSL上下文
 * @return int 配置结果：0表示成功，负数表示失败
 */
int obs_ssl_gm_configure_verification(SSL_CTX *ssl_ctx);

/**
 * @brief 国密证书验证回调函数
 *
 * SSL证书验证回调函数，用于验证SM2证书。
 *
 * @param x509_store_ctx X.509证书存储上下文
 * @param arg 用户参数
 * @return int 验证结果：1表示成功，0表示失败
 */
int obs_ssl_gm_verify_callback(X509_STORE_CTX *x509_store_ctx, void *arg);

/**
 * @brief 国密SSL上下文创建
 *
 * 创建支持国密算法的SSL上下文。
 *
 * @param ssl_version SSL版本
 * @return SSL_CTX* 创建的SSL上下文，失败返回NULL
 */
SSL_CTX *obs_ssl_gm_create_context(long ssl_version);

/**
 * @brief 国密SSL上下文配置
 *
 * 配置已创建的SSL上下文以支持国密功能。
 *
 * @param ssl_ctx SSL上下文
 * @param config HTTP请求配置
 * @return int 配置结果：0表示成功，负数表示失败
 */
int obs_ssl_gm_configure_context(SSL_CTX *ssl_ctx, const obs_http_request_option *config);

/**
 * @brief 国密SSL会话配置
 *
 * 配置SSL会话以支持国密功能。
 *
 * @param ssl SSL会话
 * @param config HTTP请求配置
 * @return int 配置结果：0表示成功，负数表示失败
 */
int obs_ssl_gm_configure_session(SSL *ssl, const obs_http_request_option *config);

/**
 * @brief 检查是否支持国密SSL
 *
 * 检查当前系统是否支持国密SSL功能。
 *
 * @return int 1表示支持，0表示不支持
 */
int obs_ssl_gm_is_supported(void);

#ifdef __cplusplus
}
#endif

#endif /* SSL_GM_CONFIG_H */