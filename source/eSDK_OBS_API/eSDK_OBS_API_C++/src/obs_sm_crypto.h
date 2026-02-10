/**
 * @file obs_sm_crypto.h
 * @brief 国密算法抽象模块
 *
 * 该模块提供统一的国密算法接口，支持自动检测Tongsuo/OpenSSL版本并选择相应的算法实现。
 * 主要支持SM2、SM3和SM4算法。
 */
#ifndef OBS_SM_CRYPTO_H
#define OBS_SM_CRYPTO_H

#include "eSDKOBS.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 初始化国密算法支持
 *
 * 该函数会检测当前环境中是否支持国密算法，并初始化相应的算法库。
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_init(void);

/**
 * @brief 检测Tongsuo/OpenSSL版本
 *
 * 该函数会检测当前使用的SSL库版本，返回版本号。
 *
 * @return int 版本号，格式为：(major << 16) | (minor << 8) | patch
 */
int obs_sm_crypto_get_version(void);

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
                 unsigned char *signature, int *sig_len);

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
                   const unsigned char *signature, int sig_len);

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
int obs_sm3_hash(const unsigned char *data, int data_len, unsigned char *digest);

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
                    unsigned char *ciphertext, int *ciphertext_len);

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
                    unsigned char *plaintext, int *plaintext_len);

/**
 * @brief 检查是否支持SM2算法
 *
 * @return int 1表示支持，0表示不支持
 */
int obs_sm_crypto_supports_sm2(void);

/**
 * @brief 检查是否支持SM3算法
 *
 * @return int 1表示支持，0表示不支持
 */
int obs_sm_crypto_supports_sm3(void);

/**
 * @brief 检查是否支持SM4算法
 *
 * @return int 1表示支持，0表示不支持
 */
int obs_sm_crypto_supports_sm4(void);

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
int obs_sm_crypto_get_support_info(char *buffer, int buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* OBS_SM_CRYPTO_H */
