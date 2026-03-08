/*********************************************************************************
* Copyright 2024 Huawei Technologies Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use
* this file except in compliance with License.  You may obtain a copy of the
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

#include "ssl_password_callback.h"
#include "log.h"
#include <openssl/ssl.h>
#include <openssl/crypto.h>

/**
 * @brief curl SSL_CTX_FUNCTION 回调
 *
 * 在 SSL 上下文创建后、握手前调用，用于延迟获取私钥密码
 *
 * 此回调在 curl 建立 SSL 连接时被触发，此时才获取密码，
 * 实现密码的延迟加载，最大程度减少密码在内存中的存在时间。
 *
 * @param curl curl 句柄
 * @param sslctx OpenSSL SSL_CTX 上下文
 * @param userdata 用户数据（obs_http_request_option 指针）
 * @return CURLcode 操作结果
 */
CURLcode ssl_password_callback(CURL *curl, void *sslctx, void *userdata)
{
    (void)curl;  // curl 参数未使用，但保留以满足函数签名

    obs_http_request_option *options = (obs_http_request_option *)userdata;

    if (!options || !options->password_callback) {
        // 没有设置密码回调，直接返回成功
        COMMLOG(OBS_LOGDEBUG, "%s No password callback set, skipping", __FUNCTION__);
        return CURLE_OK;
    }

    // 临时缓冲区存储密码（栈分配，自动清理）
    char password_buffer[256];

    // 调用用户回调获取密码
    int ret = options->password_callback(
        options->password_callback_context,
        password_buffer,
        sizeof(password_buffer)
    );

    if (ret != 0) {
        COMMLOG(OBS_LOGERROR, "%s Password callback failed", __FUNCTION__);
        // 安全擦除缓冲区（虽然可能为空，但确保安全）
        OPENSSL_cleanse(password_buffer, sizeof(password_buffer));
        return CURLE_SSL_CERTPROBLEM;
    }

    // 设置密码到 SSL_CTX
    SSL_CTX_set_default_passwd_cb_userdata((SSL_CTX *)sslctx, password_buffer);
    SSL_CTX_set_default_passwd_cb((SSL_CTX *)sslctx, NULL);  // 使用内置回调

    COMMLOG(OBS_LOGINFO, "%s Password set successfully for SSL handshake", __FUNCTION__);

    // 立即安全擦除密码缓冲区（密码已复制到 OpenSSL 内部）
    OPENSSL_cleanse(password_buffer, sizeof(password_buffer));

    return CURLE_OK;
}

/**
 * @brief 检查是否启用了密码延迟获取
 *
 * @param options 请求选项
 * @return 1 表示启用了延迟获取，0 表示未启用
 */
int is_password_lazy_loading_enabled(obs_http_request_option *options)
{
    return (options && options->password_callback) ? 1 : 0;
}
