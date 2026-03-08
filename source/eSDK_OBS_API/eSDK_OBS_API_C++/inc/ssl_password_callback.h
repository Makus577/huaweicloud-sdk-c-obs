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

#ifndef SSL_PASSWORD_CALLBACK_H
#define SSL_PASSWORD_CALLBACK_H

#include <curl/curl.h>
#include "eSDKOBS.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief curl SSL_CTX_FUNCTION 回调
 *
 * 在 SSL 上下文创建后、握手前调用，用于延迟获取私钥密码。
 * 此回调在 curl 建立 SSL 连接时被触发，此时才获取密码，
 * 实现密码的延迟加载，最大程度减少密码在内存中的存在时间。
 *
 * @param curl curl 句柄
 * @param sslctx OpenSSL SSL_CTX 上下文
 * @param userdata 用户数据（obs_http_request_option 指针）
 * @return CURLcode 操作结果
 */
CURLcode ssl_password_callback(CURL *curl, void *sslctx, void *userdata);

/**
 * @brief 检查是否启用了密码延迟获取
 *
 * @param options 请求选项
 * @return 1 表示启用了延迟获取，0 表示未启用
 */
int is_password_lazy_loading_enabled(obs_http_request_option *options);

#ifdef __cplusplus
}
#endif

#endif /* SSL_PASSWORD_CALLBACK_H */
