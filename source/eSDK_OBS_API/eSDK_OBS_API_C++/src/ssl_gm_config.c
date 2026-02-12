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
 * @file ssl_gm_config.c
 * @brief 国密SSL配置实现
 *
 * 该模块提供国密SSL配置相关功能的实现，包括国密算法检测、
 * 国密证书验证等。该模块仅在OBS_ENABLE_GM_SUPPORT=1时编译。
 */

#if OBS_ENABLE_GM_SUPPORT

#include "ssl_gm_config.h"
#include "log.h"
#include "eSDKOBS.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <string.h>

/**
 * @brief 私钥密码回调函数
 *
 * 当加载加密的私钥时，OpenSSL会调用此回调函数获取密码。
 *
 * @param buf 输出缓冲区，用于存储密码
 * @param size 缓冲区大小
 * @param rwflag 读写标志（0表示读，1表示写）
 * @param userdata 用户数据（密码字符串）
 * @return int 实际写入的密码长度
 */
static int pem_password_callback(char *buf, int size, int rwflag, void *userdata)
{
    (void)rwflag;  // 未使用，避免编译警告

    if (!userdata) {
        COMMLOG(OBS_LOGWARN, "Password callback called with NULL userdata");
        return 0;
    }

    const char *password = (const char *)userdata;
    size_t password_len = strlen(password);

    if (password_len >= (size_t)size) {
        COMMLOG(OBS_LOGERROR, "Password too long for buffer (len=%zu, buf_size=%d)",
                 password_len, size);
        return 0;
    }

    memcpy(buf, password, password_len);
    COMMLOG(OBS_LOGDEBUG, "Password provided for encrypted private key");

    return (int)password_len;
}

/**
 * @brief 国密SSL配置初始化
 *
 * 初始化国密SSL配置，包括加载国密算法、设置国密密码套件等。
 *
 * @return int 初始化结果：0表示成功，负数表示失败
 */
int obs_ssl_gm_config_init(void) {
    // 加载国密算法
    if (EVP_add_cipher(EVP_sm4_ecb()) == 0 ||
        EVP_add_cipher(EVP_sm4_cbc()) == 0 ||
        EVP_add_cipher(EVP_sm4_gcm()) == 0 ||
        EVP_add_digest(EVP_sm3()) == 0 ||
        EVP_add_cipher(EVP_sm2()) == 0) {
        COMMLOG(OBS_LOGERROR, "Failed to load GM algorithms");
        return -1;
    }

    // 检查SM2曲线是否可用
    if (!EC_GROUP_new_by_curve_name(NID_sm2)) {
        COMMLOG(OBS_LOGERROR, "SM2 curve not available");
        return -2;
    }

    COMMLOG(OBS_LOGINFO, "GM SSL configuration initialized successfully");
    return 0;
}

/**
 * @brief 国密密码套件配置
 *
 * 配置SSL上下文的国密密码套件。
 *
 * @param ssl_ctx SSL上下文
 * @param cipher_list 密码套件列表
 * @return int 配置结果：0表示成功，负数表示失败
 */
int obs_ssl_gm_configure_ciphers(SSL_CTX *ssl_ctx, const char *cipher_list) {
    if (!ssl_ctx) {
        COMMLOG(OBS_LOGERROR, "Invalid SSL context");
        return -1;
    }

    // 检查是否是Tongsuo库
    if (!SSL_CTX_has_cipher(ssl_ctx, "ECDHE-SM2-WITH-SM4-SM3")) {
        COMMLOG(OBS_LOGERROR, "Tongsuo SSL library not detected");
        return -2;
    }

    // 设置密码套件
    if (SSL_CTX_set_cipher_list(ssl_ctx, cipher_list) != 1) {
        COMMLOG(OBS_LOGERROR, "Failed to set GM cipher suite: %s", cipher_list);
        return -3;
    }

    COMMLOG(OBS_LOGINFO, "GM cipher suite configured: %s", cipher_list);
    return 0;
}

/**
 * @brief 国密证书验证配置
 *
 * 配置SSL上下文的国密证书验证方法。
 *
 * @param ssl_ctx SSL上下文
 * @return int 配置结果：0表示成功，负数表示失败
 */
int obs_ssl_gm_configure_verification(SSL_CTX *ssl_ctx) {
    if (!ssl_ctx) {
        COMMLOG(OBS_LOGERROR, "Invalid SSL context");
        return -1;
    }

    // 设置国密证书验证回调
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, obs_ssl_gm_verify_callback);
    COMMLOG(OBS_LOGINFO, "GM certificate verification configured");
    return 0;
}

/**
 * @brief 国密证书验证回调函数
 *
 * SSL证书验证回调函数，用于验证SM2证书。
 *
 * @param x509_store_ctx X.509证书存储上下文
 * @param arg 用户参数
 * @return int 验证结果：1表示成功，0表示失败
 */
int obs_ssl_gm_verify_callback(X509_STORE_CTX *x509_store_ctx, void *arg) {
    int depth = X509_STORE_CTX_get_error_depth(x509_store_ctx);
    int error = X509_STORE_CTX_get_error(x509_store_ctx);

    if (error != 0) {
        COMMLOG(OBS_LOGERROR, "Certificate verification failed at depth %d: error %d", depth, error);
        return 0;
    }

    // 获取当前证书
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_store_ctx);
    if (!cert) {
        COMMLOG(OBS_LOGERROR, "Failed to get current certificate");
        return 0;
    }

    // 检查证书公钥类型是否为SM2
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        COMMLOG(OBS_LOGERROR, "Failed to extract public key from certificate");
        return 0;
    }

    if (EVP_PKEY_id(pubkey) != EVP_PKEY_SM2) {
        COMMLOG(OBS_LOGERROR, "Certificate does not contain SM2 public key");
        EVP_PKEY_free(pubkey);
        return 0;
    }

    EVP_PKEY_free(pubkey);
    COMMLOG(OBS_LOGDEBUG, "SM2 certificate verification passed");
    return 1;
}

/**
 * @brief 国密SSL上下文创建
 *
 * 创建支持国密算法的SSL上下文。
 *
 * @param ssl_version SSL版本
 * @return SSL_CTX* 创建的SSL上下文，失败返回NULL
 */
SSL_CTX *obs_ssl_gm_create_context(long ssl_version) {
    const SSL_METHOD *method = NULL;

    // 根据SSL版本创建方法
    if (ssl_version == CURL_SSLVERSION_TLSv1_2) {
        method = TLSv1_2_method();
    } else if (ssl_version == (1 << 16) | 3) {  // TLSv1.3
        method = TLSv1_3_method();
    } else {
        COMMLOG(OBS_LOGERROR, "Unsupported SSL version for GM mode: 0x%08lX", ssl_version);
        return NULL;
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx) {
        COMMLOG(OBS_LOGERROR, "Failed to create SSL context for GM mode");
        return NULL;
    }

    // 设置默认的国密密码套件
    const char *default_ciphers = "ECDHE-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-GCM-SM3";
    if (SSL_CTX_set_cipher_list(ssl_ctx, default_ciphers) != 1) {
        COMMLOG(OBS_LOGERROR, "Failed to set default GM cipher suite");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    // 启用国密证书验证
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, obs_ssl_gm_verify_callback);

    COMMLOG(OBS_LOGINFO, "GM SSL context created successfully with version 0x%08lX", ssl_version);
    return ssl_ctx;
}

/**
 * @brief 国密SSL上下文配置
 *
 * 配置已创建的SSL上下文以支持国密功能。
 *
 * @param ssl_ctx SSL上下文
 * @param config HTTP请求配置
 * @return int 配置结果：0表示成功，负数表示失败
 */
int obs_ssl_gm_configure_context(SSL_CTX *ssl_ctx, const obs_http_request_option *config) {
    if (!ssl_ctx || !config) {
        return -1;
    }

    // 配置双向认证（如果启用）
    if (config->mutual_ssl_switch) {
        // 如果客户端私钥有密码，设置密码回调函数
        if (config->client_key_password && strlen(config->client_key_password) > 0) {
            SSL_CTX_set_default_passwd_cb(ssl_ctx, pem_password_callback);
            SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, config->client_key_password);
            COMMLOG(OBS_LOGINFO, "Private key password callback configured");
        }

        // 加载客户端证书
        if (SSL_CTX_use_certificate_file(ssl_ctx, config->client_cert_path, SSL_FILETYPE_PEM) <= 0) {
            unsigned long err = ERR_get_error();
            char err_buf[256] = {0};
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            COMMLOG(OBS_LOGERROR, "Failed to load client certificate: %s, error: %s",
                     config->client_cert_path, err_buf);
            return -2;
        }
        COMMLOG(OBS_LOGINFO, "Client certificate loaded: %s", config->client_cert_path);

        // 加载客户端私钥
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, config->client_key_path, SSL_FILETYPE_PEM) <= 0) {
            unsigned long err = ERR_get_error();
            char err_buf[256] = {0};
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            COMMLOG(OBS_LOGERROR, "Failed to load client private key: %s, error: %s",
                     config->client_key_path, err_buf);
            return -3;
        }
        COMMLOG(OBS_LOGINFO, "Client private key loaded: %s", config->client_key_path);

        // 检查证书和私钥是否匹配
        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            COMMLOG(OBS_LOGERROR, "Client certificate and private key do not match");
            return -4;
        }

        COMMLOG(OBS_LOGINFO, "Mutual SSL configured for GM mode");
    }

    return 0;
}

/**
 * @brief 国密SSL会话配置
 *
 * 配置SSL会话以支持国密功能。
 *
 * @param ssl SSL会话
 * @param config HTTP请求配置
 * @return int 配置结果：0表示成功，负数表示失败
 */
int obs_ssl_gm_configure_session(SSL *ssl, const obs_http_request_option *config) {
    if (!ssl || !config) {
        return -1;
    }

    // 启用OCSP stapling（如果配置）
    if (config->ocsp_stapling) {
        SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
        COMMLOG(OBS_LOGINFO, "OCSP stapling enabled for GM mode");
    }

    // 配置会话票证（如果启用）
    if (!config->enable_session_tickets) {
        SSL_set_session_tickets_enabled(ssl, 0);
        COMMLOG(OBS_LOGINFO, "SSL session tickets disabled for GM mode");
    }

    return 0;
}

/**
 * @brief 检查是否支持国密SSL
 *
 * 检查当前系统是否支持国密SSL功能。
 *
 * @return int 1表示支持，0表示不支持
 */
int obs_ssl_gm_is_supported(void) {
    // 检查Tongsuo特定的API是否可用
    if (SSL_library_init() != 1) {
        return 0;
    }

    // 检查SM2、SM3、SM4算法是否可用
    const EVP_MD *sm3_md = EVP_get_digestbyname("sm3");
    const EVP_CIPHER *sm4_cipher = EVP_get_cipherbyname("sm4-cbc");
    const EC_GROUP *sm2_group = EC_GROUP_new_by_curve_name(NID_sm2);

    int supported = 0;
    if (sm3_md && sm4_cipher && sm2_group) {
        supported = 1;
        COMMLOG(OBS_LOGINFO, "GM SSL support detected");
    } else {
        COMMLOG(OBS_LOGWARN, "GM SSL support not available: "
                "SM3 %s, SM4 %s, SM2 %s",
                sm3_md ? "available" : "not available",
                sm4_cipher ? "available" : "not available",
                sm2_group ? "available" : "not available");
    }

    if (sm2_group) {
        EC_GROUP_free((EC_GROUP *)sm2_group);
    }

    return supported;
}

#endif /* OBS_ENABLE_GM_SUPPORT */