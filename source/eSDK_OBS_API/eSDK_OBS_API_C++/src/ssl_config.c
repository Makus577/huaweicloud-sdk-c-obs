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
#include "ssl_config.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include "securec.h"
#include <stdlib.h>
#include <openssl/crypto.h>

/**
 * @brief 安全地分配内存用于存储敏感数据
 *
 * 使用OpenSSL的OPENSSL_secure_malloc分配内存，该内存不会被交换到磁盘
 */
static void *secure_alloc(size_t size)
{
    void *ptr = OPENSSL_secure_malloc(size);
    if (!ptr) {
        COMMLOG(OBS_LOGERROR, "%s Failed to allocate secure memory", __FUNCTION__);
    }
    return ptr;
}

/**
 * @brief 安全地复制字符串（用于敏感数据）
 */
static char *secure_strdup(const char *src)
{
    if (!src) {
        return NULL;
    }

    size_t len = strlen(src);
    char *dest = (char *)secure_alloc(len + 1);
    if (!dest) {
        return NULL;
    }

    errno_t err = memcpy_s(dest, len + 1, src, len);
    if (err != EOK) {
        COMMLOG(OBS_LOGERROR, "%s memcpy_s failed", __FUNCTION__);
        OPENSSL_secure_free(dest);
        return NULL;
    }

    dest[len] = '\0';
    return dest;
}

/**
 * @brief 安全地释放敏感数据内存
 */
static void secure_free(void **ptr)
{
    if (ptr && *ptr) {
        OPENSSL_secure_free(*ptr);
        *ptr = NULL;
    }
}

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
 *
 * 示例：
 * ```c
 * obs_http_request_option options;
 * init_http_request_option(&options);
 *
 * // 设置密码
 * set_client_key_password_secure(&options, "my_password");
 *
 * // 使用options进行SSL连接...
 *
 * // 完成后清除密码
 * clear_client_key_password_secure(&options);
 * ```
 */
int set_client_key_password_secure(obs_http_request_option *options, const char *password)
{
    if (!options) {
        COMMLOG(OBS_LOGERROR, "%s options parameter is NULL", __FUNCTION__);
        return -1;
    }

    // 如果之前已经设置了密码，先安全地释放它
    if (options->client_key_password) {
        secure_free((void **)&options->client_key_password);
    }

    // 如果新密码为NULL或空字符串，则不设置密码（表示无密码）
    if (!password || strlen(password) == 0) {
        options->client_key_password = NULL;
        COMMLOG(OBS_LOGDEBUG, "%s password cleared or not set", __FUNCTION__);
        return 0;
    }

    // 使用安全内存分配来存储密码
    char *secure_password = secure_strdup(password);
    if (!secure_password) {
        COMMLOG(OBS_LOGERROR, "%s failed to allocate secure memory for password", __FUNCTION__);
        return -1;
    }

    options->client_key_password = secure_password;
    COMMLOG(OBS_LOGDEBUG, "%s password set securely in protected memory", __FUNCTION__);
    return 0;
}

/**
 * @brief 安全地清除客户端私钥密码
 *
 * 使用OPENSSL_secure_free释放密码内存，并自动擦除内存内容。
 *
 * @param options 指向obs_http_request_option结构体的指针
 *
 * @note 调用此函数后，options->client_key_password 将被设置为NULL
 * @note 此函数会安全擦除内存内容，防止密码被内存扫描工具读取
 *
 * 示例：
 * ```c
 * // 在使用完密码后，应该立即清除
 * clear_client_key_password_secure(&options);
 * ```
 */
void clear_client_key_password_secure(obs_http_request_option *options)
{
    if (!options) {
        return;
    }

    if (options->client_key_password) {
        COMMLOG(OBS_LOGDEBUG, "%s clearing password from secure memory", __FUNCTION__);
        secure_free((void **)&options->client_key_password);
    }
}
