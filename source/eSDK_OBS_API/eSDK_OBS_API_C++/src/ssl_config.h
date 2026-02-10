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
 * @file ssl_config.h
 * @brief SSL 配置管理模块
 *
 * 该模块提供了SSL配置的初始化、加载和验证功能，支持从配置文件和环境变量
 * 加载SSL相关配置，并提供了严格的配置验证机制。
 *
 * 主要功能：
 * - 初始化HTTP请求配置选项
 * - 从ini文件加载SSL配置
 * - 从环境变量加载SSL配置
 * - 验证SSL配置的有效性
 */
#ifndef SSL_CONFIG_H
#define SSL_CONFIG_H

#include "eSDKOBS.h"

/**
 * @brief 初始化HTTP请求配置选项
 *
 * 初始化obs_http_request_option结构体，设置默认值。
 *
 * @param options 指向obs_http_request_option结构体的指针
 *
 * @note 该函数会将所有字段初始化为默认值，包括：
 * - 连接超时时间：30秒
 * - 最大连接时间：60秒
 * - 保持连接：启用
 * - 空闲保持时间：60秒
 * - 间隔时间：60秒
 * - SSL密码套件：NULL（使用默认）
 * - 禁止重用TCP连接：禁用
 * - CURL最大连接数：-1（使用默认）
 * - HTTP/2开关：关闭
 * - BBR算法开关：关闭
 * - 认证类型：协商类型
 * - 缓冲区大小：0（使用默认）
 * - 服务器证书路径：NULL
 * - CURL日志详细程度：禁用
 * - 双向证书认证开关：关闭
 * - 客户端证书路径：NULL
 * - 客户端私钥路径：NULL
 * - 客户端私钥密码：NULL
 * - 国密模式开关：关闭
 * - SSL最小版本：TLSv1.2
 * - SSL最大版本：TLSv1.3
 *
 * 示例：
 * ```c
 * obs_http_request_option request_options;
 * init_http_request_option(&request_options);
 * ```
 */
void init_http_request_option(obs_http_request_option *options);

/**
 * @brief 从配置文件加载SSL配置
 *
 * 从OBS.ini配置文件中加载SSL相关配置，包括双向认证和国密模式配置。
 *
 * @param options 指向obs_options结构体的指针，配置将加载到该结构体中
 *
 * @note 配置文件的格式如下：
 * ```ini
 * [SSLConfig]
 * MutualSSLEnabled=true
 * ClientCertPath=/path/to/client.crt
 * ClientKeyPath=/path/to/client.key
 * ClientKeyPassword=password
 * GMModeEnabled=true
 * CipherList=ECDHE-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-GCM-SM3
 * SSLMinVersion=1.2
 * SSLMaxVersion=1.2
 * ```
 *
 * @note 如果配置文件不存在或无法读取，函数会尝试从环境变量加载配置。
 *
 * 示例：
 * ```c
 * obs_options options;
 * // 初始化options结构体
 * load_ssl_config_from_ini(&options);
 * ```
 */
void load_ssl_config_from_ini(obs_options *options);

/**
 * @brief 从环境变量加载SSL配置
 *
 * 从环境变量中加载SSL相关配置，包括双向认证和国密模式配置。
 *
 * @param options 指向obs_options结构体的指针，配置将加载到该结构体中
 *
 * @note 支持的环境变量如下：
 * - OBS_MUTUAL_SSL_ENABLED：是否启用双向认证（true/false或1/0）
 * - OBS_CLIENT_CERT_PATH：客户端证书路径
 * - OBS_CLIENT_KEY_PATH：客户端私钥路径
 * - OBS_CLIENT_KEY_PASSWORD：客户端私钥密码
 * - OBS_GM_MODE_ENABLED：是否启用国密模式（true/false或1/0）
 * - OBS_SSL_CIPHER_LIST：SSL密码套件列表
 * - OBS_SSL_MIN_VERSION：SSL最小版本（1.0/1.1/1.2/1.3）
 * - OBS_SSL_MAX_VERSION：SSL最大版本（1.0/1.1/1.2/1.3）
 *
 * @note 环境变量配置的优先级高于配置文件。
 *
 * 示例：
 * ```c
 * // 在代码中设置环境变量（通常在程序外部设置）
 * setenv("OBS_MUTUAL_SSL_ENABLED", "true", 1);
 * setenv("OBS_CLIENT_CERT_PATH", "/path/to/client.crt", 1);
 * setenv("OBS_CLIENT_KEY_PATH", "/path/to/client.key", 1);
 *
 * obs_options options;
 * load_ssl_config_from_env(&options);
 * ```
 */
void load_ssl_config_from_env(obs_options *options);

/**
 * @brief 验证SSL配置的有效性
 *
 * 验证SSL配置的有效性，检查配置是否符合要求。
 *
 * @param config 指向obs_http_request_option结构体的指针，包含要验证的配置
 *
 * @return int 验证结果：
 *         0 - 配置有效
 *        -1 - 配置为NULL
 *        -2 - 双向认证已启用但未指定客户端证书路径
 *        -3 - 双向认证已启用但未指定客户端私钥路径
 *        -4 - 客户端证书文件不存在或不可读
 *        -5 - 客户端私钥文件不存在或不可读
 *        -6 - SSL最小版本大于最大版本
 *        -7 - 服务器证书路径无效
 *
 * @note 该函数会检查配置的完整性和有效性，但不会检查文件的内容是否有效。
 *
 * 示例：
 * ```c
 * obs_http_request_option request_options;
 * init_http_request_option(&request_options);
 * request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
 * request_options.client_cert_path = "/path/to/client.crt";
 * request_options.client_key_path = "/path/to/client.key";
 *
 * int result = validate_ssl_config(&request_options);
 * if (result != 0) {
 *     COMMLOG(OBS_LOGERROR, "SSL配置无效，错误代码：%d", result);
 * }
 * ```
 */
int validate_ssl_config(const obs_http_request_option *config);

#endif /* SSL_CONFIG_H */
