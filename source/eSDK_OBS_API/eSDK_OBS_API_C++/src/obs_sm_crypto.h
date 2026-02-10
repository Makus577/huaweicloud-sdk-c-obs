/**
 * @file obs_sm_crypto.h
 * @brief 国密算法抽象模块
 *
 * 该模块提供统一的国密算法接口，支持自动检测Tongsuo/OpenSSL版本并选择相应的算法实现。
 * 主要支持SM2、SM3和SM4算法，并提供硬件加速支持。
 */
#ifndef OBS_SM_CRYPTO_H
#define OBS_SM_CRYPTO_H

#include "eSDKOBS.h"

#ifdef __cplusplus
extern "C" {
#endif

// 硬件加速类型枚举
typedef enum {
    SM_CRYPTO_ACCELERATION_NONE,        // 无硬件加速
    SM_CRYPTO_ACCELERATION_INTEL_AESNI, // Intel AES-NI
    SM_CRYPTO_ACCELERATION_ARM_CE,      // ARMv8 Crypto Extensions
    SM_CRYPTO_ACCELERATION_PPC_CRYPT,   // PowerPC Crypto Extensions
    SM_CRYPTO_ACCELERATION_GENERIC      // 通用硬件加速
} sm_crypto_acceleration_type_t;

// 算法实现类型
typedef enum {
    SM_CRYPTO_IMPLEMENTATION_SOFTWARE,  // 纯软件实现
    SM_CRYPTO_IMPLEMENTATION_HARDWARE,  // 硬件加速实现
    SM_CRYPTO_IMPLEMENTATION_AUTO       // 自动选择
} sm_crypto_implementation_type_t;

// 性能统计信息
typedef struct {
    uint64_t total_bytes_processed;     // 总处理字节数
    uint64_t total_operations;          // 总操作数
    uint64_t total_time_ms;             // 总耗时（毫秒）
    double average_speed_mbps;          // 平均速度（Mbps）
} sm_crypto_performance_stats_t;

/**
 * @brief 初始化国密算法支持
 *
 * 该函数会检测当前环境中是否支持国密算法，并初始化相应的算法库。
 *
 * @param implementation 算法实现类型（软件、硬件或自动选择）
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_init(sm_crypto_implementation_type_t implementation);

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
 * @brief 检测硬件加速支持
 *
 * 该函数会检测当前系统是否支持硬件加速，并返回支持的硬件加速类型。
 *
 * @return sm_crypto_acceleration_type_t 支持的硬件加速类型
 */
sm_crypto_acceleration_type_t obs_sm_crypto_detect_acceleration(void);

/**
 * @brief 检查是否支持指定类型的硬件加速
 *
 * @param type 硬件加速类型
 * @return int 1表示支持，0表示不支持
 */
int obs_sm_crypto_supports_acceleration(sm_crypto_acceleration_type_t type);

/**
 * @brief 设置算法实现类型
 *
 * 该函数可以动态设置算法实现类型（软件或硬件加速）。
 *
 * @param implementation 算法实现类型
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_set_implementation(sm_crypto_implementation_type_t implementation);

/**
 * @brief 获取当前算法实现类型
 *
 * @return sm_crypto_implementation_type_t 当前算法实现类型
 */
sm_crypto_implementation_type_t obs_sm_crypto_get_implementation(void);

/**
 * @brief 获取性能统计信息
 *
 * 该函数返回算法操作的性能统计信息。
 *
 * @param stats 输出性能统计信息的结构体指针
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_get_performance_stats(sm_crypto_performance_stats_t *stats);

/**
 * @brief 重置性能统计信息
 *
 * 该函数重置所有性能统计计数器。
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_reset_performance_stats(void);

/**
 * @brief 获取算法支持信息
 *
 * 该函数会返回一个字符串，包含当前环境支持的国密算法信息和硬件加速信息。
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
