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
 * 该模块提供了SSL配置的初始化和验证功能。
 *
 * ## 安全原则
 * - SSL配置（特别是双向认证、国密模式）仅通过API设置
 * - 不支持从配置文件或环境变量加载敏感配置
 * - 敏感数据使用OpenSSL安全内存管理
 */

#ifndef SSL_CONFIG_H
#define SSL_CONFIG_H

#include "eSDKOBS.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 安全地设置客户端私钥密码
 *
 * 使用OPENSSL_secure_malloc分配安全内存来存储密码，
 * 并在不再需要时安全擦除内存内容。
 *
 * @param options 指向obs_http_request_option结构体的指针
 * @param password 密码字符串（将被复制到安全内存）
 * @return int 操作结果：0表示成功，-1表示失败
 *
 * @note 该函数会自动释放之前设置的密码（如果存在）
 * @note 密码存储在安全内存中，不会被交换到磁盘
 * @note 使用完成后应调用 clear_client_key_password_secure() 清除密码
 */
int set_client_key_password_secure(obs_http_request_option *options, const char *password);

/**
 * @brief 安全地清除客户端私钥密码
 *
 * 使用OPENSSL_secure_free释放密码内存，并自动擦除内存内容。
 *
 * @param options 指向obs_http_request_option结构体的指针
 *
 * @note 调用此函数后，options->client_key_password 将被设置为NULL
 */
void clear_client_key_password_secure(obs_http_request_option *options);

#ifdef __cplusplus
}
#endif

#endif /* SSL_CONFIG_H */
