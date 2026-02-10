/**
 * @file obs_sm_crypto.c
 * @brief 国密算法抽象模块实现
 *
 * 该模块提供统一的国密算法接口，支持自动检测Tongsuo/OpenSSL版本并选择相应的算法实现。
 * 主要支持SM2、SM3和SM4算法。
 */
#include "obs_sm_crypto.h"
#include "log.h"
#include <openssl/ssl.h>

/**
 * @brief 初始化国密算法支持
 *
 * 该函数会检测当前环境中是否支持国密算法，并初始化相应的算法库。
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_init(void)
{
    // 检查OpenSSL/Tongsuo库是否已初始化
    if (SSL_library_init() != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize OpenSSL library", __FUNCTION__);
        return -1;
    }

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    return 0;
}

/**
 * @brief 检测Tongsuo/OpenSSL版本
 *
 * 该函数会检测当前使用的SSL库版本，返回版本号。
 *
 * @return int 版本号，格式为：(major << 16) | (minor << 8) | patch
 */
int obs_sm_crypto_get_version(void)
{
    const char *version = SSLeay_version(SSLEAY_VERSION);
    int major, minor, patch;

    // 检查是否是Tongsuo版本
    if (strstr(version, "Tongsuo") != NULL)
    {
        if (sscanf(strstr(version, "Tongsuo"), "Tongsuo %d.%d.%d", &major, &minor, &patch) == 3)
        {
            return (major << 16) | (minor << 8) | patch;
        }
    }

    // 检测OpenSSL版本
    if (sscanf(version, "OpenSSL %d.%d.%d", &major, &minor, &patch) == 3)
    {
        return (major << 16) | (minor << 8) | patch;
    }

    COMMLOG(OBS_LOGERROR, "%s Failed to parse SSL library version: %s", __FUNCTION__, version);
    return 0;
}

/**
 * @brief 检查是否支持SM2算法
 *
 * @return int 1表示支持，0表示不支持
 */
int obs_sm_crypto_supports_sm2(void)
{
    // 检测是否支持SM2算法
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    if (md_ctx)
    {
        const EVP_MD *md = EVP_sm3();
        if (md)
        {
            EVP_MD_CTX_destroy(md_ctx);
            return 1;
        }
        EVP_MD_CTX_destroy(md_ctx);
    }

    return 0;
}

/**
 * @brief 检查是否支持SM3算法
 *
 * @return int 1表示支持，0表示不支持
 */
int obs_sm_crypto_supports_sm3(void)
{
    // 检测是否支持SM3算法
    const EVP_MD *md = EVP_sm3();
    return md != NULL;
}

/**
 * @brief 检查是否支持SM4算法
 *
 * @return int 1表示支持，0表示不支持
 */
int obs_sm_crypto_supports_sm4(void)
{
    // 检测是否支持SM4算法
    const EVP_CIPHER *cipher = EVP_sm4_ecb();
    return cipher != NULL;
}

/**
 * @brief 获取算法支持信息
 *
 * 该函数会返回一个字符串，包含当前环境支持的国密算法信息。
 *
 * @param buffer 输出缓冲区
 * @param buffer_size 缓冲区大小
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_get_support_info(char *buffer, int buffer_size)
{
    if (!buffer || buffer_size <= 0)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid parameters", __FUNCTION__);
        return -1;
    }

    int version = obs_sm_crypto_get_version();
    int supports_sm2 = obs_sm_crypto_supports_sm2();
    int supports_sm3 = obs_sm_crypto_supports_sm3();
    int supports_sm4 = obs_sm_crypto_supports_sm4();

    int len = snprintf(buffer, buffer_size,
                       "SSL Library Version: 0x%06X\n"
                       "SM2 Support: %s\n"
                       "SM3 Support: %s\n"
                       "SM4 Support: %s\n",
                       version,
                       supports_sm2 ? "Yes" : "No",
                       supports_sm3 ? "Yes" : "No",
                       supports_sm4 ? "Yes" : "No");

    if (len < 0 || len >= buffer_size)
    {
        COMMLOG(OBS_LOGERROR, "%s Buffer overflow", __FUNCTION__);
        return -2;
    }

    return 0;
}

/**
 * @brief SM3哈希
 *
 * 使用SM3算法对数据进行哈希计算。
 *
 * @param data 要哈希的数据
 * @param data_len 数据长度
 * @param digest 输出的哈希值（256位，32字节）
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm3_hash(const unsigned char *data, int data_len, unsigned char *digest)
{
    if (!data || data_len <= 0 || !digest)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid parameters", __FUNCTION__);
        return -1;
    }

    const EVP_MD *md = EVP_sm3();
    if (!md)
    {
        COMMLOG(OBS_LOGERROR, "%s SM3 algorithm not supported", __FUNCTION__);
        return -2;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    if (!md_ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create EVP_MD_CTX", __FUNCTION__);
        return -3;
    }

    if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize digest", __FUNCTION__);
        EVP_MD_CTX_destroy(md_ctx);
        return -4;
    }

    if (EVP_DigestUpdate(md_ctx, data, data_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to update digest", __FUNCTION__);
        EVP_MD_CTX_destroy(md_ctx);
        return -5;
    }

    unsigned int digest_len;
    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to finalize digest", __FUNCTION__);
        EVP_MD_CTX_destroy(md_ctx);
        return -6;
    }

    if (digest_len != 32)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid digest length: %u", __FUNCTION__, digest_len);
        EVP_MD_CTX_destroy(md_ctx);
        return -7;
    }

    EVP_MD_CTX_destroy(md_ctx);
    return 0;
}

/**
 * @brief SM4加密
 *
 * 使用SM4算法对数据进行加密。
 *
 * @param key 密钥（128位，16字节）
 * @param iv 初始化向量（128位，16字节）
 * @param plaintext 明文数据
 * @param plaintext_len 明文长度
 * @param ciphertext 输出的密文
 * @param ciphertext_len 密文长度
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm4_encrypt(const unsigned char *key, const unsigned char *iv,
                    const unsigned char *plaintext, int plaintext_len,
                    unsigned char *ciphertext, int *ciphertext_len)
{
    if (!key || !iv || !plaintext || plaintext_len <= 0 || !ciphertext || !ciphertext_len)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid parameters", __FUNCTION__);
        return -1;
    }

    const EVP_CIPHER *cipher = EVP_sm4_cbc();
    if (!cipher)
    {
        COMMLOG(OBS_LOGERROR, "%s SM4 algorithm not supported", __FUNCTION__);
        return -2;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_create();
    if (!ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create EVP_CIPHER_CTX", __FUNCTION__);
        return -3;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize encryption", __FUNCTION__);
        EVP_CIPHER_CTX_destroy(ctx);
        return -4;
    }

    int out_len1 = *ciphertext_len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len1, plaintext, plaintext_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to encrypt data", __FUNCTION__);
        EVP_CIPHER_CTX_destroy(ctx);
        return -5;
    }

    int out_len2 = *ciphertext_len - out_len1;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len1, &out_len2) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to finalize encryption", __FUNCTION__);
        EVP_CIPHER_CTX_destroy(ctx);
        return -6;
    }

    *ciphertext_len = out_len1 + out_len2;
    EVP_CIPHER_CTX_destroy(ctx);
    return 0;
}

/**
 * @brief SM4解密
 *
 * 使用SM4算法对数据进行解密。
 *
 * @param key 密钥（128位，16字节）
 * @param iv 初始化向量（128位，16字节）
 * @param ciphertext 密文数据
 * @param ciphertext_len 密文长度
 * @param plaintext 输出的明文
 * @param plaintext_len 明文长度
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm4_decrypt(const unsigned char *key, const unsigned char *iv,
                    const unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *plaintext, int *plaintext_len)
{
    if (!key || !iv || !ciphertext || ciphertext_len <= 0 || !plaintext || !plaintext_len)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid parameters", __FUNCTION__);
        return -1;
    }

    const EVP_CIPHER *cipher = EVP_sm4_cbc();
    if (!cipher)
    {
        COMMLOG(OBS_LOGERROR, "%s SM4 algorithm not supported", __FUNCTION__);
        return -2;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_create();
    if (!ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create EVP_CIPHER_CTX", __FUNCTION__);
        return -3;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize decryption", __FUNCTION__);
        EVP_CIPHER_CTX_destroy(ctx);
        return -4;
    }

    int out_len1 = *plaintext_len;
    if (EVP_DecryptUpdate(ctx, plaintext, &out_len1, ciphertext, ciphertext_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to decrypt data", __FUNCTION__);
        EVP_CIPHER_CTX_destroy(ctx);
        return -5;
    }

    int out_len2 = *plaintext_len - out_len1;
    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len1, &out_len2) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to finalize decryption", __FUNCTION__);
        EVP_CIPHER_CTX_destroy(ctx);
        return -6;
    }

    *plaintext_len = out_len1 + out_len2;
    EVP_CIPHER_CTX_destroy(ctx);
    return 0;
}

/**
 * @brief SM2签名
 *
 * 使用SM2算法对数据进行签名。
 *
 * @param private_key 私钥字符串（PEM格式）
 * @param data 要签名的数据
 * @param data_len 数据长度
 * @param signature 输出的签名
 * @param sig_len 签名长度
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm2_sign(const char *private_key, const unsigned char *data, int data_len,
                 unsigned char *signature, int *sig_len)
{
    if (!private_key || !data || data_len <= 0 || !signature || !sig_len)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid parameters", __FUNCTION__);
        return -1;
    }

    // 简单实现，需要根据实际情况完善
    // 此处需要实现从PEM格式字符串中解析私钥、创建SM2签名上下文等功能
    COMMLOG(OBS_LOGWARN, "%s SM2 signature implementation is not complete", __FUNCTION__);

    return -1;
}

/**
 * @brief SM2验证
 *
 * 使用SM2算法验证签名的真实性。
 *
 * @param public_key 公钥字符串（PEM格式）
 * @param data 要验证的数据
 * @param data_len 数据长度
 * @param signature 待验证的签名
 * @param sig_len 签名长度
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm2_verify(const char *public_key, const unsigned char *data, int data_len,
                   const unsigned char *signature, int sig_len)
{
    if (!public_key || !data || data_len <= 0 || !signature || sig_len <= 0)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid parameters", __FUNCTION__);
        return -1;
    }

    // 简单实现，需要根据实际情况完善
    // 此处需要实现从PEM格式字符串中解析公钥、创建SM2验证上下文等功能
    COMMLOG(OBS_LOGWARN, "%s SM2 verification implementation is not complete", __FUNCTION__);

    return -1;
}
