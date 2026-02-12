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
 * - 统一的配置接口和优先级管理
 */
#ifndef SSL_CONFIG_H
#define SSL_CONFIG_H

#include "eSDKOBS.h"
#include <unistd.h>

// 配置项数量
#if OBS_ENABLE_GM_SUPPORT
#define OBS_CONFIG_MAX_ITEMS 25
#else
#define OBS_CONFIG_MAX_ITEMS 24
#endif

// 配置项枚举
typedef enum {
    OBS_CONFIG_SPEED_LIMIT,
    OBS_CONFIG_SPEED_TIME,
    OBS_CONFIG_CONNECT_TIME,
    OBS_CONFIG_MAX_CONNECTED_TIME,
    OBS_CONFIG_KEEP_ALIVE,
    OBS_CONFIG_KEEP_IDLE,
    OBS_CONFIG_KEEP_INTVL,
    OBS_CONFIG_PROXY_HOST,
    OBS_CONFIG_PROXY_AUTH,
    OBS_CONFIG_SSL_CIPHER_LIST,
    OBS_CONFIG_FORBID_REUSE_TCP,
    OBS_CONFIG_CURL_MAX_CONNECTS,
    OBS_CONFIG_HTTP2_SWITCH,
    OBS_CONFIG_BBR_SWITCH,
    OBS_CONFIG_AUTH_SWITCH,
    OBS_CONFIG_BUFFER_SIZE,
    OBS_CONFIG_SERVER_CERT_PATH,
    OBS_CONFIG_CURL_LOG_VERBOSE,
    OBS_CONFIG_MUTUAL_SSL_SWITCH,
    OBS_CONFIG_CLIENT_CERT_PATH,
    OBS_CONFIG_CLIENT_KEY_PATH,
    OBS_CONFIG_CLIENT_KEY_PASSWORD,
    #if OBS_ENABLE_GM_SUPPORT
    OBS_CONFIG_GM_MODE_SWITCH,
    #endif
    OBS_CONFIG_SSL_MIN_VERSION,
    OBS_CONFIG_SSL_MAX_VERSION,
    OBS_CONFIG_OCSP_STAPLING,
    OBS_CONFIG_CERTIFICATE_PIN,
    OBS_CONFIG_CERTIFICATE_PIN_COUNT,
    OBS_CONFIG_VERIFY_HOSTNAME,
    OBS_CONFIG_ENABLE_SESSION_TICKETS,
    OBS_CONFIG_SSL_SESSION_CACHE_TIMEOUT
} obs_config_item_t;

// 配置来源枚举
typedef enum {
    CONFIG_SOURCE_DEFAULT,    // 默认配置
    CONFIG_SOURCE_INI,        // 配置文件
    CONFIG_SOURCE_ENV,        // 环境变量
    CONFIG_SOURCE_API         // API设置
} config_source_t;

// 配置变更监听回调函数类型
typedef void (*config_change_callback_t)(obs_config_item_t item, config_source_t source);

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
 * @brief 从配置文件加载SSL配置（已弃用）
 *
 * @warning 此函数已弃用，保留仅用于向后兼容。
 *
 * 出于安全考虑，SSL配置（特别是双向认证、国密模式等包含敏感信息的配置）
 * 现在仅通过API设置，不再从配置文件加载。
 *
 * @param options 指向obs_options结构体的指针（未使用）
 *
 * @note 建议使用 config_manager API 来管理配置：
 *       - config_manager_init() - 初始化配置管理器
 *       - config_manager_set() - 通过API设置配置
 *       - config_manager_get() - 获取配置
 *       - config_manager_destroy() - 销毁配置管理器
 *
 * @note 如需从配置文件加载非SSL配置，请直接使用 config_manager API。
 *
 * 示例：
 * ```c
 * // 不推荐：已弃用的方式
 * // load_ssl_config_from_ini(&options);
 *
 * // 推荐方式：使用 config_manager API
 * obs_http_request_option options;
 * init_http_request_option(&options);
 * options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
 * options.client_cert_path = "/path/to/client.crt";
 * options.client_key_path = "/path/to/client.key";
 * ```
 */
void load_ssl_config_from_ini(obs_options *options);

/**
 * @brief 从环境变量加载SSL配置（已弃用）
 *
 * @warning 此函数已弃用，保留仅用于向后兼容。
 *
 * 出于安全考虑，SSL配置（特别是双向认证、国密模式等包含敏感信息的配置）
 * 现在仅通过API设置，不再从环境变量加载。
 *
 * @param options 指向obs_options结构体的指针（未使用）
 *
 * @note 建议使用 config_manager API 来管理配置：
 *       - config_manager_init() - 初始化配置管理器
 *       - config_manager_set() - 通过API设置配置
 *       - config_manager_get() - 获取配置
 *       - config_manager_destroy() - 销毁配置管理器
 *
 * @note 如需从环境变量加载非SSL配置，请直接使用 config_manager API。
 *
 * 示例：
 * ```c
 * // 不推荐：已弃用的方式
 * // setenv("OBS_MUTUAL_SSL_ENABLED", "true", 1);
 * // load_ssl_config_from_env(&options);
 *
 * // 推荐方式：使用 config_manager API
 * obs_http_request_option options;
 * init_http_request_option(&options);
 * options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
 * options.client_cert_path = "/path/to/client.crt";
 * options.client_key_path = "/path/to/client.key";
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

/**
 * @brief 初始化配置管理系统
 *
 * 初始化全局配置上下文，加载默认配置。
 */
void config_manager_init(void);

/**
 * @brief 销毁配置管理系统
 *
 * 释放配置管理系统使用的资源。
 */
void config_manager_destroy(void);

/**
 * @brief 加载完整配置
 *
 * 从所有配置来源加载配置，按照优先级合并配置。
 *
 * @return int 加载结果：
 *         0 - 成功
 *        -1 - 配置文件加载失败
 *        -2 - 环境变量加载失败
 *        -3 - 配置验证失败
 */
int config_manager_load(void);

/**
 * @brief 获取配置
 *
 * 获取当前配置的副本。
 *
 * @param config 指向obs_http_request_option结构体的指针，用于存储配置副本
 */
void config_manager_get(obs_http_request_option *config);

/**
 * @brief 设置配置项
 *
 * 设置配置项的值，使用API来源。
 *
 * @param item 配置项
 * @param value 配置值
 *
 * @return int 设置结果：
 *         0 - 成功
 *        -1 - 无效的配置项
 *        -2 - 配置值无效
 */
int config_manager_set(obs_config_item_t item, const char *value);

/**
 * @brief 设置整数配置项
 *
 * 设置整数类型的配置项的值，使用API来源。
 *
 * @param item 配置项
 * @param value 配置值
 *
 * @return int 设置结果：
 *         0 - 成功
 *        -1 - 无效的配置项
 *        -2 - 配置值无效
 */
int config_manager_set_int(obs_config_item_t item, int value);

/**
 * @brief 获取配置项的来源
 *
 * 获取配置项的来源，用于调试和问题排查。
 *
 * @param item 配置项
 *
 * @return config_source_t 配置来源
 */
config_source_t config_manager_get_source(obs_config_item_t item);

/**
 * @brief 注册配置变更监听回调
 *
 * 注册一个回调函数，当配置变更时会被调用。
 *
 * @param callback 回调函数指针
 */
void config_manager_register_callback(config_change_callback_t callback);

/**
 * @brief 卸载配置变更监听回调
 *
 * 卸载已注册的配置变更监听回调。
 *
 * @param callback 回调函数指针
 */
void config_manager_unregister_callback(config_change_callback_t callback);

/**
 * @brief 导出配置到字符串
 *
 * 将当前配置导出到字符串，用于日志记录和调试。
 *
 * @param buffer 输出缓冲区
 * @param buffer_size 缓冲区大小
 *
 * @return int 导出结果：
 *         0 - 成功
 *        -1 - 缓冲区大小不足
 */
int config_manager_export(char *buffer, int buffer_size);

#endif /* SSL_CONFIG_H */
