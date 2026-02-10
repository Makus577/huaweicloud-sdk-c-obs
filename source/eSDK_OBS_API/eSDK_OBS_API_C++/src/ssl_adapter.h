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
 * @file ssl_adapter.h
 * @brief SSL库适配层接口
 *
 * 该模块提供统一的SSL操作接口，支持运行时SSL库检测和初始化，
 * 并根据检测结果选择对应的SSL实现。
 */

#ifndef SSL_ADAPTER_H
#define SSL_ADAPTER_H

#include "eSDKOBS.h"

// SSL库类型枚举
typedef enum {
    OBS_SSL_LIBRARY_DEFAULT,  // 自动检测
    OBS_SSL_LIBRARY_OPENSSL,  // 标准OpenSSL
    OBS_SSL_LIBRARY_TONGSUO   // 国密Tongsuo
} obs_ssl_library_t;

/**
 * @brief 运行时SSL库检测
 *
 * 检测当前系统中可用的SSL库类型。
 *
 * @return obs_ssl_library_t SSL库类型
 */
obs_ssl_library_t obs_ssl_detect_library(void);

/**
 * @brief SSL库初始化
 *
 * 初始化SSL库，根据库类型选择对应的初始化方法。
 *
 * @param library_type SSL库类型
 * @return int 初始化结果：0表示成功，负数表示失败
 */
int obs_ssl_init(obs_ssl_library_t library_type);

/**
 * @brief 全局SSL初始化
 *
 * 自动检测并初始化SSL库。
 *
 * @return int 初始化结果：0表示成功，负数表示失败
 */
int obs_ssl_global_init(void);

/**
 * @brief 双向认证设置
 *
 * 为SSL上下文设置双向认证配置。
 *
 * @param config HTTP请求配置
 * @return int 设置结果：0表示成功，负数表示失败
 */
int obs_ssl_setup_mutual_auth(obs_http_request_option *config);

/**
 * @brief 国密模式设置
 *
 * 为SSL上下文设置国密模式配置。
 *
 * @param config HTTP请求配置
 * @return int 设置结果：0表示成功，负数表示失败
 */
#if OBS_ENABLE_GM_SUPPORT
int obs_ssl_setup_gm_mode(obs_http_request_option *config);
#endif

/**
 * @brief 国密支持初始化
 *
 * 初始化国密功能支持。
 *
 * @return int 初始化结果：0表示成功，负数表示失败
 */
#if OBS_ENABLE_GM_SUPPORT
int obs_ssl_init_gm_support(void);
#endif

/**
 * @brief 设置国密密码套件
 *
 * 设置SSL上下文的国密密码套件。
 *
 * @param cipher_list 密码套件列表
 * @return int 设置结果：0表示成功，负数表示失败
 */
#if OBS_ENABLE_GM_SUPPORT
int obs_ssl_setup_gm_ciphers(const char *cipher_list);
#endif

/**
 * @brief 设置国密证书验证
 *
 * 设置国密模式下的证书验证方法。
 *
 * @return int 设置结果：0表示成功，负数表示失败
 */
#if OBS_ENABLE_GM_SUPPORT
int obs_ssl_setup_gm_certificate_verification(void);
#endif

/**
 * @brief SM2证书验证回调
 *
 * 国密模式下的证书验证回调函数。
 *
 * @param ssl SSL对象
 * @param x509_store_ctx X.509存储上下文
 * @return int 验证结果：1表示成功，0表示失败
 */
#if OBS_ENABLE_GM_SUPPORT
int obs_gm_certificate_verify_callback(X509_STORE_CTX *x509_store_ctx, void *arg);
#endif

/**
 * @brief OpenSSL双向认证设置
 *
 * 为标准OpenSSL设置双向认证配置。
 *
 * @param config HTTP请求配置
 * @return int 设置结果：0表示成功，负数表示失败
 */
int obs_ssl_setup_mutual_auth_openssl(obs_http_request_option *config);

/**
 * @brief Tongsuo双向认证设置
 *
 * 为Tongsuo库设置双向认证配置。
 *
 * @param config HTTP请求配置
 * @return int 设置结果：0表示成功，负数表示失败
 */
#if OBS_ENABLE_GM_SUPPORT
int obs_ssl_setup_mutual_auth_tongsuo(obs_http_request_option *config);
#endif

#endif /* SSL_ADAPTER_H */