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
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/**
 * @brief 安全地分配内存用于存储敏感数据
 *
 * 使用OpenSSL的OPENSSL_secure_malloc分配内存，该内存不会被交换到磁盘
 *
 * @param size 要分配的内存大小
 * @return void* 分配的内存指针，失败返回NULL
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
 *
 * 使用安全内存分配，并在复制后进行验证
 *
 * @param src 源字符串
 * @return char* 新分配的安全内存中的副本，失败返回NULL
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
 *
 * 使用OPENSSL_secure_free释放内存，并自动清零内存内容
 *
 * @param ptr 指向要释放内存的指针的指针
 */
static void secure_free(void **ptr)
{
    if (ptr && *ptr) {
        OPENSSL_secure_free(*ptr);
        *ptr = NULL;
    }
}

/**
 * @brief 验证证书文件格式是否有效（PEM格式）
 *
 * 尝试加载证书文件，验证其是否为有效的PEM格式
 *
 * @param cert_path 证书文件路径
 * @return int 0=格式有效，-1=格式无效或文件无法读取
 */
static int validate_certificate_format(const char *cert_path)
{
    if (!cert_path) {
        return -1;
    }

    FILE *fp = fopen(cert_path, "r");
    if (!fp) {
        return -1;
    }

    // 尝试读取PEM格式的证书
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!cert) {
        // 不是有效的X509证书，尝试读取私钥
        fp = fopen(cert_path, "r");
        if (fp) {
            EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
            fclose(fp);
            if (pkey) {
                EVP_PKEY_free(pkey);
                return 0;  // 是有效的私钥
            }
        }
        return -1;  // 既不是证书也不是私钥
    }

    X509_free(cert);
    return 0;  // 是有效的证书
}

/**
 * @brief 验证私钥密码是否正确
 *
 * 尝试使用提供的密码解密私钥，验证密码是否正确
 *
 * @param key_path 私钥文件路径
 * @param password 私钥密码（可为NULL表示无密码）
 * @return int 0=密码正确，-1=密码错误或文件无法读取
 */
static int validate_private_key_password(const char *key_path, const char *password)
{
    if (!key_path) {
        return -1;
    }

    FILE *fp = fopen(key_path, "r");
    if (!fp) {
        return -1;
    }

    // 尝试使用密码读取私钥
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, (void *)password);
    fclose(fp);

    if (!pkey) {
        // 密码错误或格式错误
        return -1;
    }

    EVP_PKEY_free(pkey);
    return 0;  // 密码正确
}

/**
 * @brief 验证证书和私钥是否匹配
 *
 * 验证给定的证书和私钥是否构成有效的密钥对
 *
 * @param cert_path 证书文件路径
 * @param key_path 私钥文件路径
 * @return int 0=匹配，-1=不匹配或文件无法读取
 */
static int validate_cert_key_match(const char *cert_path, const char *key_path)
{
    if (!cert_path || !key_path) {
        return -1;
    }

    // 读取证书
    FILE *cert_fp = fopen(cert_path, "r");
    if (!cert_fp) {
        return -1;
    }
    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);

    if (!cert) {
        return -1;
    }

    // 读取私钥
    FILE *key_fp = fopen(key_path, "r");
    if (!key_fp) {
        X509_free(cert);
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);

    if (!pkey) {
        X509_free(cert);
        return -1;
    }

    // 验证证书和私钥是否匹配
    int match = X509_check_private_key(cert, pkey);

    X509_free(cert);
    EVP_PKEY_free(pkey);

    return (match == 1) ? 0 : -1;
}

// 验证SSL配置的有效性
int validate_ssl_config(const obs_http_request_option *config)
{
    if (config == NULL)
    {
        COMMLOG(OBS_LOGERROR, "%s SSL configuration is NULL", __FUNCTION__);
        return -1;
    }

    int validation_result = 0;

#if OBS_ENABLE_GM_SUPPORT
    // Case 3: 国密关闭但指定了加密证书路径 - 记录INFO日志
    if (config->gm_mode_switch == OBS_GM_MODE_CLOSE &&
        config->client_enc_cert_path != NULL)
    {
        COMMLOG(OBS_LOGINFO, "%s GM mode is CLOSED, ignoring provided encrypt certificates", __FUNCTION__);
    }
#endif

    // 验证双向认证配置
    if (config->mutual_ssl_switch == OBS_MUTUAL_SSL_OPEN)
    {
        if (!config->client_cert_path || strlen(config->client_cert_path) == 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Mutual SSL enabled but client certificate path not specified", __FUNCTION__);
            validation_result = -2;
        }
        else if (!config->client_key_path || strlen(config->client_key_path) == 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Mutual SSL enabled but client key path not specified", __FUNCTION__);
            validation_result = -3;
        }
        else
        {
            // 检查证书文件是否存在且可读
            if (access(config->client_cert_path, R_OK) != 0)
            {
                COMMLOG(OBS_LOGERROR, "%s Client certificate file not found or unreadable: %s", __FUNCTION__, config->client_cert_path);
                validation_result = -4;
            }
            // 检查密钥文件是否存在且可读
            else if (access(config->client_key_path, R_OK) != 0)
            {
                COMMLOG(OBS_LOGERROR, "%s Client key file not found or unreadable: %s", __FUNCTION__, config->client_key_path);
                validation_result = -5;
            }
            // Case 8: 验证证书格式是否有效（PEM格式）
            else if (validate_certificate_format(config->client_cert_path) != 0)
            {
                COMMLOG(OBS_LOGERROR, "%s Client certificate file is not valid PEM format: %s", __FUNCTION__, config->client_cert_path);
                validation_result = -7;
            }
            // Case 10: 验证私钥格式是否有效
            else if (validate_certificate_format(config->client_key_path) != 0)
            {
                COMMLOG(OBS_LOGERROR, "%s Client key file is not valid PEM format: %s", __FUNCTION__, config->client_key_path);
                validation_result = -8;
            }
            // Case 9: 验证证书和私钥是否匹配
            else if (validate_cert_key_match(config->client_cert_path, config->client_key_path) != 0)
            {
                COMMLOG(OBS_LOGERROR, "%s Client certificate and key do not match: cert=%s, key=%s", __FUNCTION__, config->client_cert_path, config->client_key_path);
                validation_result = -9;
            }
            // Case 10: 验证私钥密码是否正确（如果提供了密码）
            else if (config->client_key_password != NULL &&
                     validate_private_key_password(config->client_key_path, config->client_key_password) != 0)
            {
                COMMLOG(OBS_LOGERROR, "%s Client key password is incorrect: %s", __FUNCTION__, config->client_key_path);
                validation_result = -10;
            }
        }
    }

    // 验证服务器证书路径（如果提供）
    if (config->server_cert_path && strlen(config->server_cert_path) > 0)
    {
        if (access(config->server_cert_path, R_OK) != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Server certificate file not found or unreadable: %s", __FUNCTION__, config->server_cert_path);
            validation_result = -6;
        }
    }

#if OBS_ENABLE_GM_SUPPORT
    // Case 11: 国密+双向认证联合场景验证
    if (config->gm_mode_switch == OBS_GM_MODE_OPEN &&
        config->mutual_ssl_switch == OBS_MUTUAL_SSL_OPEN)
    {
        // 检查是否同时提供了国密证书和双向认证证书
        if (config->client_cert_path != NULL)
        {
            // 在这种情况下，我们使用同一套证书进行国密和双向认证
            // 记录日志说明配置情况
            COMMLOG(OBS_LOGINFO, "%s GM mode and mutual SSL both enabled, using same certificate for both: %s", __FUNCTION__, config->client_cert_path);
        }
        else
        {
            // Case 1 已经被处理：国密开启但证书缺失
            // 这里不需要额外处理，因为上面的Case 1检查已经会报错
        }
    }
#endif

    // 输出验证结果详细信息
    if (validation_result != 0)
    {
        COMMLOG(OBS_LOGDEBUG, "%s SSL configuration validation failed with error code: %d", __FUNCTION__, validation_result);
    }
    else
    {
        COMMLOG(OBS_LOGDEBUG, "%s SSL configuration validation passed", __FUNCTION__);
    }

    return validation_result;
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

