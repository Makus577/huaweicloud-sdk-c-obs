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
 * @file ssl_adapter.c
 * @brief SSL库适配层实现
 *
 * 该模块提供统一的SSL操作接口，支持运行时SSL库检测和初始化，
 * 并根据检测结果选择对应的SSL实现。
 */

#include "ssl_adapter.h"
#include "log.h"
#include "eSDKOBS.h"

#if OBS_ENABLE_GM_SUPPORT
#include <openssl/ssl.h>  // Tongsuo OpenSSL兼容接口
#endif

// 全局SSL库类型变量
static obs_ssl_library_t g_ssl_library = OBS_SSL_LIBRARY_DEFAULT;

/**
 * @brief 运行时SSL库检测
 *
 * 检测当前系统中可用的SSL库类型。
 *
 * @return obs_ssl_library_t SSL库类型
 */
obs_ssl_library_t obs_ssl_detect_library(void) {
    if (g_ssl_library != OBS_SSL_LIBRARY_DEFAULT) {
        return g_ssl_library;
    }

    // 首先尝试检测Tongsuo库（如果启用了国密功能）
    #if OBS_ENABLE_GM_SUPPORT
    // 检测Tongsuo特定的API
    if (SSL_library_init() == 1) {
        // 尝试加载Tongsuo特定的国密算法
        if (EVP_add_cipher(EVP_sm4_ecb()) &&
            EVP_add_digest(EVP_sm3()) &&
            EVP_add_cipher(EVP_sm4_cbc())) {
            COMMLOG(OBS_LOGINFO, "Tongsuo SSL library detected");
            g_ssl_library = OBS_SSL_LIBRARY_TONGSUO;
            return g_ssl_library;
        }
    }
    #endif

    // 默认情况下使用标准OpenSSL
    COMMLOG(OBS_LOGINFO, "Standard OpenSSL library detected");
    g_ssl_library = OBS_SSL_LIBRARY_OPENSSL;
    return g_ssl_library;
}

/**
 * @brief SSL库初始化
 *
 * 初始化SSL库，根据库类型选择对应的初始化方法。
 *
 * @param library_type SSL库类型
 * @return int 初始化结果：0表示成功，负数表示失败
 */
int obs_ssl_init(obs_ssl_library_t library_type) {
    if (g_ssl_library != OBS_SSL_LIBRARY_DEFAULT && g_ssl_library != library_type) {
        COMMLOG(OBS_LOGWARN, "SSL library already initialized as %d, changing to %d",
                g_ssl_library, library_type);
    }

    switch (library_type) {
        case OBS_SSL_LIBRARY_OPENSSL:
            // 标准OpenSSL初始化
            if (SSL_library_init() != 1) {
                COMMLOG(OBS_LOGERROR, "Failed to initialize OpenSSL");
                return -1;
            }
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();
            g_ssl_library = OBS_SSL_LIBRARY_OPENSSL;
            COMMLOG(OBS_LOGINFO, "Standard OpenSSL initialized successfully");
            break;

        #if OBS_ENABLE_GM_SUPPORT
        case OBS_SSL_LIBRARY_TONGSUO:
            // Tongsuo库初始化
            if (SSL_library_init() != 1) {
                COMMLOG(OBS_LOGERROR, "Failed to initialize Tongsuo");
                return -1;
            }
            OpenSSL_add_all_algorithms();
            SSL_load_error_strings();

            // 加载Tongsuo特定的国密算法
            EVP_add_cipher(EVP_sm4_ecb());
            EVP_add_cipher(EVP_sm4_cbc());
            EVP_add_cipher(EVP_sm4_gcm());
            EVP_add_digest(EVP_sm3());
            EVP_add_cipher(EVP_sm2());

            g_ssl_library = OBS_SSL_LIBRARY_TONGSUO;
            COMMLOG(OBS_LOGINFO, "Tongsuo SSL library initialized successfully");
            break;
        #endif

        default:
            COMMLOG(OBS_LOGERROR, "Invalid SSL library type: %d", library_type);
            return -2;
    }

    return 0;
}

/**
 * @brief 全局SSL初始化
 *
 * 自动检测并初始化SSL库。
 *
 * @return int 初始化结果：0表示成功，负数表示失败
 */
int obs_ssl_global_init(void) {
    // 首先检测可用的SSL库
    obs_ssl_library_t library_type = obs_ssl_detect_library();

    // 初始化SSL库
    int result = obs_ssl_init(library_type);
    if (result != 0) {
        return result;
    }

    // 如果启用了国密功能，初始化国密配置
    #if OBS_ENABLE_GM_SUPPORT
    if (library_type == OBS_SSL_LIBRARY_TONGSUO) {
        result = obs_ssl_init_gm_support();
        if (result != 0) {
            COMMLOG(OBS_LOGERROR, "Failed to initialize GM support: %d", result);
            return result;
        }
    }
    #endif

    return 0;
}

/**
 * @brief 双向认证设置
 *
 * 为SSL上下文设置双向认证配置。
 *
 * @param config HTTP请求配置
 * @return int 设置结果：0表示成功，负数表示失败
 */
int obs_ssl_setup_mutual_auth(obs_http_request_option *config) {
    if (!config) {
        COMMLOG(OBS_LOGERROR, "Invalid config parameter");
        return -1;
    }

    if (config->mutual_ssl_switch) {
        if (!config->client_cert_path || !config->client_key_path) {
            COMMLOG(OBS_LOGERROR, "Mutual SSL enabled but client certificate or key path not specified");
            return -2;
        }

        // 验证证书和密钥文件存在
        if (access(config->client_cert_path, R_OK) != 0 ||
            access(config->client_key_path, R_OK) != 0) {
            COMMLOG(OBS_LOGERROR, "Client certificate or key file not accessible: %s, %s",
                    config->client_cert_path, config->client_key_path);
            return -3;
        }

        // 根据SSL库类型设置双向认证
        obs_ssl_library_t ssl_lib = obs_ssl_detect_library();
        switch (ssl_lib) {
            case OBS_SSL_LIBRARY_OPENSSL:
                return obs_ssl_setup_mutual_auth_openssl(config);
            #if OBS_ENABLE_GM_SUPPORT
            case OBS_SSL_LIBRARY_TONGSUO:
                return obs_ssl_setup_mutual_auth_tongsuo(config);
            #endif
            default:
                COMMLOG(OBS_LOGERROR, "Unsupported SSL library for mutual authentication: %d", ssl_lib);
                return -4;
        }
    }

    return 0;  // 双向认证已禁用
}

/**
 * @brief 国密模式设置
 *
 * 为SSL上下文设置国密模式配置。
 *
 * @param config HTTP请求配置
 * @return int 设置结果：0表示成功，负数表示失败
 */
#if OBS_ENABLE_GM_SUPPORT
int obs_ssl_setup_gm_mode(obs_http_request_option *config) {
    if (!config || !config->gm_mode_switch) {
        return 0;  // 国密模式未启用
    }

    // 验证Tongsuo库是否可用
    if (obs_ssl_detect_library() != OBS_SSL_LIBRARY_TONGSUO) {
        COMMLOG(OBS_LOGERROR, "GM mode requires Tongsuo library");
        return -1;
    }

    // 国密模式下的SSL配置
    int result = obs_ssl_setup_gm_ciphers(config->ssl_cipher_list);
    if (result != 0) {
        return result;
    }

    return obs_ssl_setup_gm_certificate_verification();
}
#endif

/**
 * @brief 国密支持初始化
 *
 * 初始化国密功能支持。
 *
 * @return int 初始化结果：0表示成功，负数表示失败
 */
#if OBS_ENABLE_GM_SUPPORT
int obs_ssl_init_gm_support(void) {
    // 检查Tongsuo库是否已初始化
    if (g_ssl_library != OBS_SSL_LIBRARY_TONGSUO) {
        return -1;
    }

    // 初始化SM2曲线参数
    EC_GROUP *sm2_group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (!sm2_group) {
        COMMLOG(OBS_LOGERROR, "Failed to create SM2 curve group");
        return -2;
    }

    EC_GROUP_free(sm2_group);

    // 检查SM3、SM4算法是否可用
    const EVP_MD *sm3_md = EVP_get_digestbyname("sm3");
    const EVP_CIPHER *sm4_cipher = EVP_get_cipherbyname("sm4-cbc");

    if (!sm3_md || !sm4_cipher) {
        COMMLOG(OBS_LOGERROR, "SM3 or SM4 algorithm not available");
        return -3;
    }

    COMMLOG(OBS_LOGINFO, "GM algorithm support initialized successfully");
    return 0;
}
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
int obs_ssl_setup_gm_ciphers(const char *cipher_list) {
    if (!cipher_list) {
        // 使用默认国密密码套件
        const char *default_ciphers = "ECDHE-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-GCM-SM3";
        COMMLOG(OBS_LOGINFO, "Using default GM cipher suite: %s", default_ciphers);
    } else {
        // 注意：密码套件将在request.c中通过curl_easy_setopt设置
        COMMLOG(OBS_LOGINFO, "Using custom GM cipher suite: %s", cipher_list);
    }

    return 0;
}
#endif

/**
 * @brief 设置国密证书验证
 *
 * 设置国密模式下的证书验证方法。
 *
 * @return int 设置结果：0表示成功，负数表示失败
 */
#if OBS_ENABLE_GM_SUPPORT
int obs_ssl_setup_gm_certificate_verification(void) {
    // 注意：证书验证回调已在 request.c 的 setup_CA 函数中通过 CURLOPT_SSL_CTX_FUNCTION 设置
    // 这里仅作占位，实际验证逻辑在 sslctx_function 回调中实现
    COMMLOG(OBS_LOGINFO, "GM certificate verification callback configured");

    return 0;
}
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
int obs_gm_certificate_verify_callback(X509_STORE_CTX *x509_store_ctx, void *arg) {
    // 简化的SM2证书验证实现
    // 实际应用中需要更详细的验证逻辑
    int depth = X509_STORE_CTX_get_error_depth(x509_store_ctx);
    int error = X509_STORE_CTX_get_error(x509_store_ctx);

    if (error != 0) {
        COMMLOG(OBS_LOGERROR, "Certificate verification failed at depth %d: error %d", depth, error);
        return 0;
    }

    // 检查证书是否包含SM2公钥
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_store_ctx);
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        COMMLOG(OBS_LOGERROR, "Failed to extract public key from certificate");
        return 0;
    }

    int key_type = EVP_PKEY_id(pubkey);
    EVP_PKEY_free(pubkey);

    if (key_type != EVP_PKEY_SM2) {
        COMMLOG(OBS_LOGERROR, "Certificate does not contain SM2 public key");
        return 0;
    }

    COMMLOG(OBS_LOGDEBUG, "SM2 certificate verification passed");
    return 1;
}
#endif