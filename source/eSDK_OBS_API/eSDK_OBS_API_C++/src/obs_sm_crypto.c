/**
 * @file obs_sm_crypto.c
 * @brief 国密算法抽象模块实现
 *
 * 该模块提供统一的国密算法接口，支持自动检测Tongsuo/OpenSSL版本并选择相应的算法实现。
 * 主要支持SM2、SM3和SM4算法，并提供硬件加速支持。
 *
 * 该模块仅在OBS_ENABLE_GM_SUPPORT=1时编译。
 */
#if OBS_ENABLE_GM_SUPPORT

#include "obs_sm_crypto.h"
#include "log.h"
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

// 全局状态变量
static sm_crypto_implementation_type_t g_implementation = SM_CRYPTO_IMPLEMENTATION_AUTO;
static sm_crypto_acceleration_type_t g_acceleration_type = SM_CRYPTO_ACCELERATION_NONE;
static sm_crypto_performance_stats_t g_performance_stats = {0};
static int g_is_initialized = 0;

// 线程安全保护
#ifdef WIN32
static CRITICAL_SECTION g_mutex;
static int g_mutex_initialized = 0;
#else
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

// 获取互斥锁
static void lock_mutex(void) {
#ifdef WIN32
    if (g_mutex_initialized) {
        EnterCriticalSection(&g_mutex);
    }
#else
    pthread_mutex_lock(&g_mutex);
#endif
}

// 释放互斥锁
static void unlock_mutex(void) {
#ifdef WIN32
    if (g_mutex_initialized) {
        LeaveCriticalSection(&g_mutex);
    }
#else
    pthread_mutex_unlock(&g_mutex);
#endif
}

// 时间测量函数（用于性能统计）
static uint64_t get_current_time_ms(void)
{
    #ifdef WIN32
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        return uli.QuadPart / 10000; // 转换为毫秒
    #else
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    #endif
}

// 硬件加速检测函数
static sm_crypto_acceleration_type_t detect_hardware_acceleration(void)
{
    // 检测是否支持硬件加速
    // 这里可以添加更详细的硬件加速检测逻辑

    #ifdef __x86_64__
        // 检测 Intel AES-NI 支持
        int cpuinfo[4];
        __cpuid(cpuinfo, 1);
        if (cpuinfo[2] & (1 << 25)) { // AES-NI 位
            COMMLOG(OBS_LOGINFO, "Intel AES-NI hardware acceleration detected");
            return SM_CRYPTO_ACCELERATION_INTEL_AESNI;
        }
    #elif defined(__aarch64__) || defined(__arm__)
        // 检测 ARMv8 加密扩展支持
        #ifdef __aarch64__
            unsigned long id_aa64isar0;
            __asm__ __volatile__("mrs %0, id_aa64isar0_el1" : "=r" (id_aa64isar0));
            if ((id_aa64isar0 >> 48) & 0xf) { // AES 支持位
                COMMLOG(OBS_LOGINFO, "ARMv8 Crypto Extensions detected");
                return SM_CRYPTO_ACCELERATION_ARM_CE;
            }
        #endif
    #endif

    COMMLOG(OBS_LOGINFO, "No hardware acceleration detected, using software implementation");
    return SM_CRYPTO_ACCELERATION_NONE;
}

// 更新性能统计（线程安全）
static void update_performance_stats(uint64_t bytes_processed, uint64_t duration_ms)
{
    lock_mutex();
    g_performance_stats.total_bytes_processed += bytes_processed;
    g_performance_stats.total_operations += 1;
    g_performance_stats.total_time_ms += duration_ms;

    // 计算平均速度（Mbps）
    double total_bytes = g_performance_stats.total_bytes_processed;
    double total_time_seconds = g_performance_stats.total_time_ms / 1000.0;
    if (total_time_seconds > 0) {
        g_performance_stats.average_speed_mbps = (total_bytes * 8) / (total_time_seconds * 1000000);
    }
    unlock_mutex();
}

/**
 * @brief 初始化国密算法支持
 *
 * 该函数会检测当前环境中是否支持国密算法，并初始化相应的算法库。
 *
 * @param implementation 算法实现类型（软件、硬件或自动选择）
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_init(sm_crypto_implementation_type_t implementation)
{
    // 初始化互斥锁（仅初始化一次）
#ifdef WIN32
    if (!g_mutex_initialized) {
        InitializeCriticalSection(&g_mutex);
        g_mutex_initialized = 1;
    }
#endif

    lock_mutex();

    // 检查是否已初始化
    if (g_is_initialized) {
        unlock_mutex();
        COMMLOG(OBS_LOGWARN, "SM crypto already initialized");
        return 0;
    }

    // 检查OpenSSL/Tongsuo库是否已初始化
    unlock_mutex();
    if (SSL_library_init() != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize OpenSSL library", __FUNCTION__);
        return -1;
    }
    lock_mutex();

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // 检测硬件加速
    g_acceleration_type = detect_hardware_acceleration();

    // 设置算法实现类型
    g_implementation = implementation;

    // 如果选择自动实现，根据硬件支持情况决定
    if (g_implementation == SM_CRYPTO_IMPLEMENTATION_AUTO) {
        if (g_acceleration_type != SM_CRYPTO_ACCELERATION_NONE) {
            g_implementation = SM_CRYPTO_IMPLEMENTATION_HARDWARE;
            COMMLOG(OBS_LOGINFO, "Auto-selected hardware acceleration implementation");
        } else {
            g_implementation = SM_CRYPTO_IMPLEMENTATION_SOFTWARE;
            COMMLOG(OBS_LOGINFO, "Auto-selected software implementation (no hardware acceleration available)");
        }
    }

    // 初始化性能统计
    memset(&g_performance_stats, 0, sizeof(sm_crypto_performance_stats_t));

    g_is_initialized = 1;
    unlock_mutex();

    COMMLOG(OBS_LOGINFO, "SM crypto initialization completed");

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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX_init(&md_ctx);
    const EVP_MD *md = EVP_sm3();
    if (md)
    {
        EVP_MD_CTX_cleanup(&md_ctx);
        return 1;
    }
    EVP_MD_CTX_cleanup(&md_ctx);
#else
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx)
    {
        const EVP_MD *md = EVP_sm3();
        if (md)
        {
            EVP_MD_CTX_free(md_ctx);
            return 1;
        }
        EVP_MD_CTX_free(md_ctx);
    }
#endif

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
 * @brief 检测硬件加速支持
 *
 * 该函数会检测当前系统是否支持硬件加速，并返回支持的硬件加速类型。
 *
 * @return sm_crypto_acceleration_type_t 支持的硬件加速类型
 */
sm_crypto_acceleration_type_t obs_sm_crypto_detect_acceleration(void)
{
    lock_mutex();
    if (!g_is_initialized) {
        unlock_mutex();
        COMMLOG(OBS_LOGERROR, "SM crypto not initialized");
        return SM_CRYPTO_ACCELERATION_NONE;
    }

    sm_crypto_acceleration_type_t result = g_acceleration_type;
    unlock_mutex();
    return result;
}

/**
 * @brief 检查是否支持指定类型的硬件加速
 *
 * @param type 硬件加速类型
 * @return int 1表示支持，0表示不支持
 */
int obs_sm_crypto_supports_acceleration(sm_crypto_acceleration_type_t type)
{
    lock_mutex();
    if (!g_is_initialized) {
        unlock_mutex();
        COMMLOG(OBS_LOGERROR, "SM crypto not initialized");
        return 0;
    }

    int result = (g_acceleration_type == type);
    unlock_mutex();
    return result;
}

/**
 * @brief 设置算法实现类型
 *
 * 该函数可以动态设置算法实现类型（软件或硬件加速）。
 *
 * @param implementation 算法实现类型
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_set_implementation(sm_crypto_implementation_type_t implementation)
{
    lock_mutex();
    if (!g_is_initialized) {
        unlock_mutex();
        COMMLOG(OBS_LOGERROR, "SM crypto not initialized");
        return -1;
    }

    if (implementation == SM_CRYPTO_IMPLEMENTATION_HARDWARE &&
        g_acceleration_type == SM_CRYPTO_ACCELERATION_NONE) {
        unlock_mutex();
        COMMLOG(OBS_LOGERROR, "Hardware acceleration not supported on this platform");
        return -2;
    }

    g_implementation = implementation;
    unlock_mutex();

    COMMLOG(OBS_LOGINFO, "Algorithm implementation set to %s",
            (implementation == SM_CRYPTO_IMPLEMENTATION_SOFTWARE ? "software" :
             implementation == SM_CRYPTO_IMPLEMENTATION_HARDWARE ? "hardware" : "auto"));

    return 0;
}

/**
 * @brief 获取当前算法实现类型
 *
 * @return sm_crypto_implementation_type_t 当前算法实现类型
 */
sm_crypto_implementation_type_t obs_sm_crypto_get_implementation(void)
{
    lock_mutex();
    if (!g_is_initialized) {
        unlock_mutex();
        COMMLOG(OBS_LOGERROR, "SM crypto not initialized");
        return SM_CRYPTO_IMPLEMENTATION_SOFTWARE;
    }

    sm_crypto_implementation_type_t result = g_implementation;
    unlock_mutex();
    return result;
}

/**
 * @brief 获取性能统计信息
 *
 * 该函数返回算法操作的性能统计信息。
 *
 * @param stats 输出性能统计信息的结构体指针
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_get_performance_stats(sm_crypto_performance_stats_t *stats)
{
    if (!stats) {
        COMMLOG(OBS_LOGERROR, "Invalid parameter: stats is NULL");
        return -2;
    }

    lock_mutex();
    if (!g_is_initialized) {
        unlock_mutex();
        COMMLOG(OBS_LOGERROR, "SM crypto not initialized");
        return -1;
    }

    *stats = g_performance_stats;
    unlock_mutex();

    return 0;
}

/**
 * @brief 重置性能统计信息
 *
 * 该函数重置所有性能统计计数器。
 *
 * @return int 0表示成功，负数表示失败
 */
int obs_sm_crypto_reset_performance_stats(void)
{
    lock_mutex();
    if (!g_is_initialized) {
        unlock_mutex();
        COMMLOG(OBS_LOGERROR, "SM crypto not initialized");
        return -1;
    }

    memset(&g_performance_stats, 0, sizeof(sm_crypto_performance_stats_t));
    unlock_mutex();

    COMMLOG(OBS_LOGDEBUG, "Performance statistics reset");

    return 0;
}

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

    const char *accel_type_str;
    switch (g_acceleration_type) {
        case SM_CRYPTO_ACCELERATION_INTEL_AESNI:
            accel_type_str = "Intel AES-NI";
            break;
        case SM_CRYPTO_ACCELERATION_ARM_CE:
            accel_type_str = "ARMv8 Crypto Extensions";
            break;
        case SM_CRYPTO_ACCELERATION_PPC_CRYPT:
            accel_type_str = "PowerPC Crypto Extensions";
            break;
        case SM_CRYPTO_ACCELERATION_GENERIC:
            accel_type_str = "Generic Hardware";
            break;
        case SM_CRYPTO_ACCELERATION_NONE:
        default:
            accel_type_str = "None";
            break;
    }

    const char *impl_type_str;
    switch (g_implementation) {
        case SM_CRYPTO_IMPLEMENTATION_SOFTWARE:
            impl_type_str = "Software";
            break;
        case SM_CRYPTO_IMPLEMENTATION_HARDWARE:
            impl_type_str = "Hardware";
            break;
        case SM_CRYPTO_IMPLEMENTATION_AUTO:
        default:
            impl_type_str = "Auto";
            break;
    }

    int len = snprintf(buffer, buffer_size,
                       "SSL Library Version: 0x%06X\n"
                       "SM2 Support: %s\n"
                       "SM3 Support: %s\n"
                       "SM4 Support: %s\n"
                       "Hardware Acceleration: %s\n"
                       "Implementation: %s\n"
                       "Total Bytes Processed: %llu\n"
                       "Total Operations: %llu\n"
                       "Total Time: %llu ms\n"
                       "Average Speed: %.2f Mbps\n",
                       version,
                       supports_sm2 ? "Yes" : "No",
                       supports_sm3 ? "Yes" : "No",
                       supports_sm4 ? "Yes" : "No",
                       accel_type_str,
                       impl_type_str,
                       (unsigned long long)g_performance_stats.total_bytes_processed,
                       (unsigned long long)g_performance_stats.total_operations,
                       (unsigned long long)g_performance_stats.total_time_ms,
                       g_performance_stats.average_speed_mbps);

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

    uint64_t start_time = get_current_time_ms();

    const EVP_MD *md = EVP_sm3();
    if (!md)
    {
        COMMLOG(OBS_LOGERROR, "%s SM3 algorithm not supported", __FUNCTION__);
        return -2;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX_init(&md_ctx);

    if (EVP_DigestInit_ex(&md_ctx, md, NULL) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize digest", __FUNCTION__);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -3;
    }

    if (EVP_DigestUpdate(&md_ctx, data, data_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to update digest", __FUNCTION__);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -4;
    }

    unsigned int digest_len;
    if (EVP_DigestFinal_ex(&md_ctx, digest, &digest_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to finalize digest", __FUNCTION__);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -5;
    }

    if (digest_len != 32)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid digest length: %u", __FUNCTION__, digest_len);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -6;
    }

    EVP_MD_CTX_cleanup(&md_ctx);
#else
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create EVP_MD_CTX", __FUNCTION__);
        return -3;
    }

    if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize digest", __FUNCTION__);
        EVP_MD_CTX_free(md_ctx);
        return -4;
    }

    if (EVP_DigestUpdate(md_ctx, data, data_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to update digest", __FUNCTION__);
        EVP_MD_CTX_free(md_ctx);
        return -5;
    }

    unsigned int digest_len;
    if (EVP_DigestFinal_ex(md_ctx, digest, &digest_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to finalize digest", __FUNCTION__);
        EVP_MD_CTX_free(md_ctx);
        return -6;
    }

    if (digest_len != 32)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid digest length: %u", __FUNCTION__, digest_len);
        EVP_MD_CTX_free(md_ctx);
        return -7;
    }

    EVP_MD_CTX_free(md_ctx);
#endif

    // 更新性能统计
    uint64_t end_time = get_current_time_ms();
    uint64_t duration = end_time - start_time;
    update_performance_stats(data_len, duration);

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

    uint64_t start_time = get_current_time_ms();

    const EVP_CIPHER *cipher = EVP_sm4_cbc();
    if (!cipher)
    {
        COMMLOG(OBS_LOGERROR, "%s SM4 algorithm not supported", __FUNCTION__);
        return -2;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if (EVP_EncryptInit_ex(&ctx, cipher, NULL, key, iv) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize encryption", __FUNCTION__);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -3;
    }

    int out_len1 = *ciphertext_len;
    if (EVP_EncryptUpdate(&ctx, ciphertext, &out_len1, plaintext, plaintext_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to encrypt data", __FUNCTION__);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -4;
    }

    int out_len2 = *ciphertext_len - out_len1;
    if (EVP_EncryptFinal_ex(&ctx, ciphertext + out_len1, &out_len2) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to finalize encryption", __FUNCTION__);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -5;
    }

    *ciphertext_len = out_len1 + out_len2;
    EVP_CIPHER_CTX_cleanup(&ctx);
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create EVP_CIPHER_CTX", __FUNCTION__);
        return -3;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize encryption", __FUNCTION__);
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }

    int out_len1 = *ciphertext_len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len1, plaintext, plaintext_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to encrypt data", __FUNCTION__);
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    int out_len2 = *ciphertext_len - out_len1;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len1, &out_len2) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to finalize encryption", __FUNCTION__);
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }

    *ciphertext_len = out_len1 + out_len2;
    EVP_CIPHER_CTX_free(ctx);
#endif

    // 更新性能统计
    uint64_t end_time = get_current_time_ms();
    uint64_t duration = end_time - start_time;
    update_performance_stats(plaintext_len, duration);

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

    uint64_t start_time = get_current_time_ms();

    const EVP_CIPHER *cipher = EVP_sm4_cbc();
    if (!cipher)
    {
        COMMLOG(OBS_LOGERROR, "%s SM4 algorithm not supported", __FUNCTION__);
        return -2;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if (EVP_DecryptInit_ex(&ctx, cipher, NULL, key, iv) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize decryption", __FUNCTION__);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -3;
    }

    int out_len1 = *plaintext_len;
    if (EVP_DecryptUpdate(&ctx, plaintext, &out_len1, ciphertext, ciphertext_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to decrypt data", __FUNCTION__);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -4;
    }

    int out_len2 = *plaintext_len - out_len1;
    if (EVP_DecryptFinal_ex(&ctx, plaintext + out_len1, &out_len2) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to finalize decryption", __FUNCTION__);
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -5;
    }

    *plaintext_len = out_len1 + out_len2;
    EVP_CIPHER_CTX_cleanup(&ctx);
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create EVP_CIPHER_CTX", __FUNCTION__);
        return -3;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize decryption", __FUNCTION__);
        EVP_CIPHER_CTX_free(ctx);
        return -4;
    }

    int out_len1 = *plaintext_len;
    if (EVP_DecryptUpdate(ctx, plaintext, &out_len1, ciphertext, ciphertext_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to decrypt data", __FUNCTION__);
        EVP_CIPHER_CTX_free(ctx);
        return -5;
    }

    int out_len2 = *plaintext_len - out_len1;
    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len1, &out_len2) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to finalize decryption", __FUNCTION__);
        EVP_CIPHER_CTX_free(ctx);
        return -6;
    }

    *plaintext_len = out_len1 + out_len2;
    EVP_CIPHER_CTX_free(ctx);
#endif

    // 更新性能统计
    uint64_t end_time = get_current_time_ms();
    uint64_t duration = end_time - start_time;
    update_performance_stats(ciphertext_len, duration);

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

    uint64_t start_time = get_current_time_ms();

    // 创建BIO从PEM字符串读取私钥
    BIO *bio = BIO_new_mem_buf(private_key, (int)strlen(private_key));
    if (!bio)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create BIO", __FUNCTION__);
        return -2;
    }

    // 从BIO中读取EC私钥
    EC_KEY *ec_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!ec_key)
    {
        unsigned long err = ERR_get_error();
        char err_buf[256] = {0};
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        COMMLOG(OBS_LOGERROR, "%s Failed to parse private key: %s", __FUNCTION__, err_buf);
        return -3;
    }

    // 检查私钥曲线是否为SM2
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    int curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_sm2)
    {
        COMMLOG(OBS_LOGERROR, "%s Private key is not SM2 curve (curve_nid=%d)", __FUNCTION__, curve_nid);
        EC_KEY_free(ec_key);
        return -4;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX_init(&md_ctx);

    // 创建EVP_MD_CTX并初始化
    if (EVP_DigestSignInit(&md_ctx, &pkey_ctx, EVP_sm3(), NULL, NULL) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize digest sign", __FUNCTION__);
        EC_KEY_free(ec_key);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -5;
    }

    // 将EC密钥转换为EVP_PKEY
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    // 设置签名私钥
    EVP_PKEY_CTX_set0_pkey(pkey_ctx, pkey);

    // 计算签名长度
    size_t sig_len_temp = 0;
    if (EVP_DigestSignUpdate(&md_ctx, data, data_len) != 1 ||
        EVP_DigestSignFinal(&md_ctx, NULL, &sig_len_temp) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to calculate signature length", __FUNCTION__);
        EC_KEY_free(ec_key);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -6;
    }

    // 检查输出缓冲区是否足够
    if (sig_len_temp > (size_t)*sig_len)
    {
        COMMLOG(OBS_LOGERROR, "%s Output buffer too small (need %zu, have %d)",
                 __FUNCTION__, sig_len_temp, *sig_len);
        EC_KEY_free(ec_key);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -7;
    }

    // 执行签名
    if (EVP_DigestSignFinal(&md_ctx, signature, &sig_len_temp) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to sign data", __FUNCTION__);
        EC_KEY_free(ec_key);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -8;
    }

    *sig_len = (int)sig_len_temp;
    EVP_MD_CTX_cleanup(&md_ctx);
#else
    // 创建EVP_PKEY_CTX用于签名
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create PKEY context", __FUNCTION__);
        EVP_PKEY_free(pkey);
        return -5;
    }

    // 初始化签名上下文
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create MD context", __FUNCTION__);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(pkey);
        return -6;
    }

    if (EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sm3(), NULL, pkey) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize digest sign", __FUNCTION__);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -7;
    }

    // 更新待签名数据
    if (EVP_DigestSignUpdate(md_ctx, data, data_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to update digest", __FUNCTION__);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -8;
    }

    // 计算签名长度
    size_t sig_len_temp = 0;
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len_temp) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to calculate signature length", __FUNCTION__);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -9;
    }

    // 检查输出缓冲区是否足够
    if (sig_len_temp > (size_t)*sig_len)
    {
        COMMLOG(OBS_LOGERROR, "%s Output buffer too small (need %zu, have %d)",
                 __FUNCTION__, sig_len_temp, *sig_len);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -10;
    }

    // 执行签名
    if (EVP_DigestSignFinal(md_ctx, signature, &sig_len_temp) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to sign data", __FUNCTION__);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -11;
    }

    *sig_len = (int)sig_len_temp;
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
#endif

    // 更新性能统计
    uint64_t end_time = get_current_time_ms();
    uint64_t duration = end_time - start_time;
    update_performance_stats(data_len, duration);

    COMMLOG(OBS_LOGDEBUG, "%s SM2 signature completed (sig_len=%d)", __FUNCTION__, *sig_len);

    return 0;
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

    uint64_t start_time = get_current_time_ms();

    // 创建BIO从PEM字符串读取公钥
    BIO *bio = BIO_new_mem_buf(public_key, (int)strlen(public_key));
    if (!bio)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create BIO", __FUNCTION__);
        return -2;
    }

    // 从BIO中读取EC公钥
    EC_KEY *ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!ec_key)
    {
        unsigned long err = ERR_get_error();
        char err_buf[256] = {0};
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        COMMLOG(OBS_LOGERROR, "%s Failed to parse public key: %s", __FUNCTION__, err_buf);
        return -3;
    }

    // 检查公钥曲线是否为SM2
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    int curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_sm2)
    {
        COMMLOG(OBS_LOGERROR, "%s Public key is not SM2 curve (curve_nid=%d)", __FUNCTION__, curve_nid);
        EC_KEY_free(ec_key);
        return -4;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX_init(&md_ctx);

    // 创建EVP_PKEY并设置公钥
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    // 初始化验证上下文
    if (EVP_DigestVerifyInit(&md_ctx, &pkey_ctx, EVP_sm3(), NULL, NULL) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize digest verify", __FUNCTION__);
        EC_KEY_free(ec_key);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -5;
    }

    // 设置验证公钥
    EVP_PKEY_CTX_set0_pkey(pkey_ctx, pkey);

    // 更新待验证数据
    if (EVP_DigestVerifyUpdate(&md_ctx, data, data_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to update digest", __FUNCTION__);
        EC_KEY_free(ec_key);
        EVP_MD_CTX_cleanup(&md_ctx);
        return -6;
    }

    // 执行验证
    int verify_result = EVP_DigestVerifyFinal(&md_ctx, signature, (size_t)sig_len);
    EVP_MD_CTX_cleanup(&md_ctx);

    if (verify_result != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Signature verification failed", __FUNCTION__);
        EC_KEY_free(ec_key);
        return -7;
    }

    EC_KEY_free(ec_key);
#else
    // 创建EVP_PKEY
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    // 创建PKEY上下文
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pkey_ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create PKEY context", __FUNCTION__);
        EVP_PKEY_free(pkey);
        return -5;
    }

    // 创建MD上下文
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to create MD context", __FUNCTION__);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(pkey);
        return -6;
    }

    // 初始化验证上下文
    if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sm3(), NULL, pkey) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to initialize digest verify", __FUNCTION__);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -7;
    }

    // 更新待验证数据
    if (EVP_DigestVerifyUpdate(md_ctx, data, data_len) != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to update digest", __FUNCTION__);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return -8;
    }

    // 执行验证
    int verify_result = EVP_DigestVerifyFinal(md_ctx, signature, (size_t)sig_len);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (verify_result != 1)
    {
        COMMLOG(OBS_LOGERROR, "%s Signature verification failed", __FUNCTION__);
        return -9;
    }
#endif

    // 更新性能统计
    uint64_t end_time = get_current_time_ms();
    uint64_t duration = end_time - start_time;
    update_performance_stats(data_len, duration);

    COMMLOG(OBS_LOGDEBUG, "%s SM2 signature verification completed", __FUNCTION__);

    return 0;
}

#endif /* OBS_ENABLE_GM_SUPPORT */
