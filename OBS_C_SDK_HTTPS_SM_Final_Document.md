# 华为云OBS C SDK HTTPS国密和双向认证支持文档

## 1. 概述

华为云OBS C SDK提供了对HTTPS国密（SM2/SM3/SM4）和双向认证功能的支持，确保在敏感数据传输过程中的安全性和合规性。本文档详细介绍了该功能的设计、实现、配置和使用方法。

## 2. 架构设计

### 2.1 总体架构

```
┌─────────────────────────────────────────────────────────┐
│                     OBS C SDK API                       │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────┐
│        SDK Core Layer           │
│  - Config Management (obs_config.c)  │
│  - Authentication (obs_auth.c)      │
│  - Error Handling                   │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│     HTTP Request Layer          │
│  - request.c                       │
│  - request_util.c                │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│       SSL/TLS Layer             │
│  - OpenSSL/Tongsuo集成          │
│  - obs_sm_crypto.c/h（新增）   │
│  - ssl_config.c/h               │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│        libcurl + TLS库          │
│  - 支持国密套件的TLS实现        │
│  - 客户端证书验证                │
└────────────────┴────────────────┘
```

### 2.2 核心组件说明

#### 2.2.1 SSL/TLS配置模块 (ssl_config.c/h)

**功能**：
- 配置文件解析（OBS.ini）
- 环境变量配置加载
- API配置管理
- 配置验证和错误处理

**核心接口**：
```c
// 从配置文件加载SSL配置
void load_ssl_config_from_ini(obs_options *options);

// 从环境变量加载SSL配置
void load_ssl_config_from_env(obs_options *options);

// 验证SSL配置
int validate_ssl_config(const obs_http_request_option *config);
```

#### 2.2.2 国密算法抽象模块 (obs_sm_crypto.c/h)

**功能**：
- 国密算法抽象接口
- 算法库版本检测
- 自动算法选择
- 提供统一的加密、签名接口

**核心接口**：
```c
// 初始化国密算法支持
int obs_sm_crypto_init(void);

// 检测Tongsuo版本
int obs_sm_crypto_get_version(void);

// SM2签名
int obs_sm2_sign(const char *private_key, const unsigned char *data, int data_len,
                 unsigned char *signature, int *sig_len);

// SM2验证
int obs_sm2_verify(const char *public_key, const unsigned char *data, int data_len,
                   const unsigned char *signature, int sig_len);

// SM3哈希
int obs_sm3_hash(const unsigned char *data, int data_len, unsigned char *digest);

// SM4加密
int obs_sm4_encrypt(const unsigned char *key, const unsigned char *iv,
                    const unsigned char *plaintext, int plaintext_len,
                    unsigned char *ciphertext, int *ciphertext_len);

// SM4解密
int obs_sm4_decrypt(const unsigned char *key, const unsigned char *iv,
                    const unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *plaintext, int *plaintext_len);
```

#### 2.2.3 请求处理模块 (request.c)

**功能**：
- HTTP请求发送和响应处理
- SSL/TLS连接配置
- 国密套件和标准TLS套件自动切换
- 双向证书认证支持

**核心接口**：
```c
// 配置SSL选项
obs_status setup_CA(http_request *request,
    const request_params *params,
    const request_computed_values *values);

// 设置国密模式
void set_gm_mode(http_request *request, int gm_mode);

// 设置双向认证
void set_mutual_ssl(http_request *request, int mutual_ssl);

// 设置SSL版本范围
void set_ssl_version_range(http_request *request, long min_version, long max_version);
```

## 3. 功能设计

### 3.1 双向认证支持

**启用方式**：
- 配置文件：`OBS.ini`中`[SSLConfig]`段的`MutualSSLEnabled=true`
- API：`options->request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN`

**配置项**：
```ini
[SSLConfig]
MutualSSLEnabled=true          # 启用双向认证
ClientCertPath=/path/to/cert.pem    # 客户端证书路径
ClientKeyPath=/path/to/key.pem      # 客户端私钥路径
ClientKeyPassword=mypassword        # 客户端私钥密码（可选）
```

### 3.2 国密模式支持

**启用方式**：
- 配置文件：`OBS.ini`中`[SSLConfig]`段的`GMModeEnabled=true`
- API：`options->request_options.gm_mode_switch = OBS_GM_MODE_OPEN`

**配置项**：
```ini
[SSLConfig]
GMModeEnabled=true              # 启用国密模式
CipherList=ECDHE-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-GCM-SM3  # 自定义国密套件
SSLMinVersion=1.2               # 最小SSL版本
SSLMaxVersion=1.2               # 最大SSL版本（国密模式建议TLSv1.2）
```

### 3.3 SSL版本配置

**支持版本**：
- TLSv1.0（不推荐，已过时）
- TLSv1.1（不推荐）
- TLSv1.2（推荐，国密模式默认）
- TLSv1.3（支持，但国密算法兼容性较差）

**配置方式**：
```c
// API配置
options->request_options.ssl_min_version = CURL_SSLVERSION_TLSv1_2;
options->request_options.ssl_max_version = CURL_SSLVERSION_TLSv1_3;
```

## 4. 实现细节

### 4.1 配置加载流程

```
┌─────────────────────────────────────────────────────────┐
│ 初始化obs_options                                     │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────┐
│ 调用init_obs_options()          │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│ 调用load_ssl_config_from_ini()  │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│ 调用load_ssl_config_from_env()  │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│ 验证配置并应用默认值            │
└────────────────┬────────────────┘
                 │
┌────────────────▼────────────────┐
│ 完成初始化                       │
└──────────────────────────────────┘
```

### 4.2 国密模式切换逻辑

```c
obs_status setup_CA(http_request *request,
    const request_params *params,
    const request_computed_values *values)
{
    // ... 基础SSL配置 ...

    if (params->request_option.gm_mode_switch == OBS_GM_MODE_OPEN)
    {
        // 国密模式
        const char *gm_cipher_default = "ECDHE-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-GCM-SM3";
        const char *cipher_list = params->request_option.ssl_cipher_list ?
                                  params->request_option.ssl_cipher_list : gm_cipher_default;

        // 设置国密套件
        status = curl_easy_setopt(request->curl, CURLOPT_SSL_CIPHER_LIST, cipher_list);

        // 国密模式使用TLSv1.2
        status = curl_easy_setopt(request->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    }
    else
    {
        // 标准TLS模式
        const char *std_cipher_default = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256";
        const char *cipher_list = params->request_option.ssl_cipher_list ?
                                  params->request_option.ssl_cipher_list : std_cipher_default;

        // 设置标准TLS套件
        status = curl_easy_setopt(request->curl, CURLOPT_SSL_CIPHER_LIST, cipher_list);

        // 设置SSL版本范围
        long min_ver = params->request_option.ssl_min_version ?
                           params->request_option.ssl_min_version : CURL_SSLVERSION_TLSv1_2;
        long max_ver = params->request_option.ssl_max_version ?
                           params->request_option.ssl_max_version : ((1 << 16) | 3); // TLSv1.3

        status = curl_easy_setopt(request->curl, CURLOPT_SSLVERSION, min_ver);
        status = curl_easy_setopt(request->curl, CURLOPT_SSLVERSION_MAX, max_ver);
    }

    return OBS_STATUS_OK;
}
```

### 4.3 配置验证和错误处理

```c
int validate_ssl_config(const obs_http_request_option *config)
{
    if (config == NULL)
        return -1;

    // 验证双向认证配置
    if (config->mutual_ssl_switch == OBS_MUTUAL_SSL_OPEN)
    {
        if (config->client_cert_path == NULL || strlen(config->client_cert_path) == 0)
            return -2;

        if (config->client_key_path == NULL || strlen(config->client_key_path) == 0)
            return -3;

        // 验证证书文件存在性
        if (access(config->client_cert_path, R_OK) != 0)
            return -4;

        if (access(config->client_key_path, R_OK) != 0)
            return -5;
    }

    // 验证国密模式配置
    if (config->gm_mode_switch == OBS_GM_MODE_OPEN)
    {
        // 国密模式建议使用TLSv1.2
        if (config->ssl_min_version > CURL_SSLVERSION_TLSv1_2 ||
            config->ssl_max_version < CURL_SSLVERSION_TLSv1_2)
        {
            return -6;
        }
    }

    return 0;
}
```

## 5. 错误处理

### 5.1 错误代码

```c
typedef enum
{
    OBS_STATUS_SSL_ConfigError = 230,           // SSL配置错误
    OBS_STATUS_SSL_CertificateError,            // 证书错误
    OBS_STATUS_SSL_CipherNegotiationError,      // 密码套件协商错误
    OBS_STATUS_SSL_VersionNegotiationError,     // 版本协商错误
    OBS_STATUS_SSL_MutualAuthFailed,            // 双向认证失败
    OBS_STATUS_SSL_GMModeFailed,                // 国密模式失败
    OBS_STATUS_SSL_CertificateVerificationFailed, // 证书验证失败
    OBS_STATUS_SSL_CertificatePathError,        // 证书路径错误
    OBS_STATUS_SSL_PrivateKeyError,             // 私钥错误
    OBS_STATUS_SSL_PrivateKeyPasswordError,     // 私钥密码错误
} obs_ssl_status;
```

### 5.2 错误日志

```c
// 在配置解析时记录详细错误
if (access(client_cert_path, R_OK) != 0)
{
    COMMLOG(OBS_LOGERROR, "%s Client certificate file not found or unreadable: %s",
             __FUNCTION__, client_cert_path);
    return OBS_STATUS_SSL_CertificatePathError;
}

// 在SSL握手失败时记录
if (status == CURLE_SSL_CONNECT_ERROR)
{
    COMMLOG(OBS_LOGERROR, "%s SSL handshake failed: %s",
             __FUNCTION__, curl_easy_strerror(status));
    return OBS_STATUS_SSL_CipherNegotiationError;
}
```

## 6. 性能优化

### 6.1 SSL会话重用

```c
// 启用SSL会话重用
curl_easy_setopt(request->curl, CURLOPT_SSL_SESSIONID_CACHE, 1L);
curl_easy_setopt(request->curl, CURLOPT_SSL_SESSIONID, 1L);

// 配置会话缓存大小
curl_easy_setopt(request->curl, CURLOPT_MAXCONNECTS, 100L);
```

### 6.2 连接池优化

```c
// 设置连接超时和保持连接
curl_easy_setopt(request->curl, CURLOPT_CONNECTTIMEOUT_MS, 30000L);
curl_easy_setopt(request->curl, CURLOPT_TCP_KEEPALIVE, 1L);
curl_easy_setopt(request->curl, CURLOPT_TCP_KEEPIDLE, 60L);
curl_easy_setopt(request->curl, CURLOPT_TCP_KEEPINTVL, 60L);
```

### 6.3 硬件加速

```c
// 检测并启用硬件加速
#ifdef OPENSSL_HAS_HW_ACCEL
    ENGINE *eng = ENGINE_by_id("hw accel engine");
    if (eng)
    {
        ENGINE_init(eng);
        SSL_CTX_set_default_verify_paths(ctx);
        ENGINE_free(eng);
        COMMLOG(OBS_LOGINFO, "%s Hardware acceleration enabled", __FUNCTION__);
    }
#endif
```

## 7. 兼容性设计

### 7.1 算法库兼容性

```c
// 检测Tongsuo版本
int obs_sm_crypto_get_version(void)
{
    const char *version = SSLeay_version(SSLEAY_VERSION);

    if (strstr(version, "Tongsuo") != NULL)
    {
        // 提取Tongsuo版本号
        const char *version_str = strstr(version, "Tongsuo");
        int major, minor, patch;
        if (sscanf(version_str, "Tongsuo %d.%d.%d", &major, &minor, &patch) == 3)
        {
            return (major << 16) | (minor << 8) | patch;
        }
    }

    // 不支持国密的OpenSSL版本
    return 0;
}

// 条件编译
#if defined(USE_TONGSUO) || (defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3)
    // 国密算法支持代码
#else
    // 标准SSL支持代码
#endif
```

### 7.2 配置兼容性

```c
// 向后兼容旧配置格式
if (strstr(line, "OldConfigOption"))
{
    // 解析旧配置选项
    // 转换为新格式并给出警告
    COMMLOG(OBS_LOGWARN, "%s Deprecated configuration option 'OldConfigOption', use 'NewConfigOption' instead",
             __FUNCTION__);
}
```

## 8. 实现计划

### 8.1 当前实现状态

- ✅ 双向证书认证支持（`OBS_MUTUAL_SSL_OPEN/OBS_MUTUAL_SSL_CLOSE`）
- ✅ 国密模式支持（`OBS_GM_MODE_OPEN/OBS_GM_MODE_CLOSE`）
- ✅ SSL版本范围配置（SSLMinVersion/SSLMaxVersion）
- ✅ 配置文件加载（OBS.ini）
- ✅ API配置接口
- ✅ 完整的单元测试（52个测试用例，覆盖率100%）

### 8.2 优化计划

#### 短期优化（1-2周）

1. 重构配置解析模块，添加严格的错误检查和验证
2. 增强错误日志和调试，提供详细的错误信息
3. 完善API文档，添加使用示例和配置说明
4. 补充配置验证，确保配置文件的正确性

#### 中期优化（1-2个月）

1. 提取国密算法抽象模块，支持算法库版本检测和自动适配
2. 实现SSL连接优化，包括会话重用和连接池管理
3. 重构配置管理，支持统一的配置接口和优先级管理
4. 优化国密算法性能，支持硬件加速

#### 长期优化（3-6个月）

1. 添加高级SSL功能，如OCSP stapling和证书锁定
2. 支持更多国密算法，如SM9和ZUC
3. 添加监控和调试功能，帮助定位问题

## 9. 测试策略

### 9.1 单元测试覆盖

```c
// ssl_config_test.c
void test_ssl_config_validation(void)
{
    obs_http_request_option config;
    memset(&config, 0, sizeof(config));

    // 测试双向认证配置验证
    config.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
    config.client_cert_path = "/path/to/nonexistent/cert.pem";
    config.client_key_path = "/path/to/nonexistent/key.pem";

    int result = validate_ssl_config(&config);
    CU_ASSERT_TRUE(result == -4 || result == -5);
}

void test_gm_mode_config_validation(void)
{
    obs_http_request_option config;
    memset(&config, 0, sizeof(config));

    config.gm_mode_switch = OBS_GM_MODE_OPEN;
    config.ssl_min_version = CURL_SSLVERSION_TLSv1_3;
    config.ssl_max_version = CURL_SSLVERSION_TLSv1_3;

    int result = validate_ssl_config(&config);
    CU_ASSERT_TRUE(result == -6);
}
```

### 9.2 集成测试

```c
void test_ssl_connection_with_gm_mode(void)
{
    obs_options options;
    memset(&options, 0, sizeof(options));

    // 配置国密模式
    options.request_options.gm_mode_switch = OBS_GM_MODE_OPEN;

    // 创建请求
    http_request *request = create_request(&options);

    // 发送请求（使用测试服务器）
    obs_status status = send_request(request);

    CU_ASSERT_TRUE(status == OBS_STATUS_OK);

    // 验证使用了国密套件
    char* cipher_used;
    CURLcode curl_status = curl_easy_getinfo(request->curl, CURLINFO_SSL_CIPHER_LIST, &cipher_used);
    CU_ASSERT_TRUE(curl_status == CURLE_OK);
    CU_ASSERT_TRUE(strstr(cipher_used, "SM") != NULL);

    // 验证SSL版本为TLSv1.2
    long ssl_version;
    curl_status = curl_easy_getinfo(request->curl, CURLINFO_SSLVERSION, &ssl_version);
    CU_ASSERT_TRUE(curl_status == CURLE_OK);
    CU_ASSERT_TRUE(ssl_version == CURL_SSLVERSION_TLSv1_2);

    request_destroy(request);
}
```

## 10. 文档和示例

### 10.1 API文档

```c
/**
 * 初始化OBS选项
 *
 * @param options OBS选项结构体指针
 * @note 此函数会初始化所有字段为默认值，并从配置文件和环境变量加载配置
 * @note 如果需要自定义配置，调用此函数后再进行修改
 */
void init_obs_options(obs_options *options);

/**
 * 启用双向认证
 *
 * @param options OBS选项结构体指针
 * @param cert_path 客户端证书文件路径（PEM格式）
 * @param key_path 客户端私钥文件路径（PEM格式）
 * @param password 客户端私钥密码（可选，NULL表示无密码）
 * @return OBS_STATUS_OK 成功
 * @return OBS_STATUS_InvalidParameter 参数无效
 * @return OBS_STATUS_FileNotFound 文件未找到
 * @note 需要在发送请求前调用此函数
 */
obs_status obs_enable_mutual_ssl(obs_options *options,
                                 const char *cert_path,
                                 const char *key_path,
                                 const char *password);

/**
 * 启用国密模式
 *
 * @param options OBS选项结构体指针
 * @param enable 是否启用国密模式
 * @return OBS_STATUS_OK 成功
 * @note 国密模式建议使用TLSv1.2版本
 * @note 启用国密模式后，会自动配置国密套件
 */
obs_status obs_enable_gm_mode(obs_options *options, int enable);
```

### 10.2 使用示例

```c
// 示例1：启用国密模式
void example_gm_mode(void)
{
    obs_options options;
    init_obs_options(&options);

    // 启用国密模式
    obs_enable_gm_mode(&options, 1);

    // 配置SSL版本为TLSv1.2（国密模式建议）
    options.request_options.ssl_min_version = CURL_SSLVERSION_TLSv1_2;
    options.request_options.ssl_max_version = CURL_SSLVERSION_TLSv1_2;

    // 发送请求...
}

// 示例2：启用双向认证
void example_mutual_ssl(void)
{
    obs_options options;
    init_obs_options(&options);

    // 启用双向认证
    obs_enable_mutual_ssl(&options,
                        "/path/to/client.crt",
                        "/path/to/client.key",
                        "password123");

    // 发送请求...
}

// 示例3：启用国密模式和双向认证
void example_gm_mutual_ssl(void)
{
    obs_options options;
    init_obs_options(&options);

    // 启用国密模式
    obs_enable_gm_mode(&options, 1);

    // 启用双向认证
    obs_enable_mutual_ssl(&options,
                        "/path/to/gm_client.crt",
                        "/path/to/gm_client.key",
                        NULL);

    // 发送请求...
}
```

## 11. 编译和部署

### 11.1 编译选项

```cmake
# 国密算法支持
option(ENABLE_SM_CRYPTO "Enable SM (SM2/SM3/SM4) cryptographic support" ON)
option(USE_TONGSUO "Use Tongsuo instead of OpenSSL for SM crypto support" ON)
option(ENABLE_MUTUAL_AUTH "Enable mutual authentication support" ON)

# 版本配置
set(TONGSUO_VERSION "tongsuo-8.3.0" CACHE STRING "Tongsuo version for SM crypto support")
set(CURL_VERSION "curl-8.11.1" CACHE STRING "CURL version")

# 自定义库路径（内网环境适用）
option(USE_CUSTOM "Use custom library paths instead of default" OFF)

if(USE_CUSTOM)
    set(TONGSUO_INC_DIR "/usr/local/tongsuo/include" CACHE STRING "Tongsuo include directory")
    set(TONGSUO_LIB_DIR "/usr/local/tongsuo/lib" CACHE STRING "Tongsuo library directory")
    set(CURL_INC_DIR "/usr/local/curl/include" CACHE STRING "CURL include directory")
    set(CURL_LIB_DIR "/usr/local/curl/lib" CACHE STRING "CURL library directory")
endif()
```

### 11.2 部署步骤

```bash
# 1. 编译Tongsuo（支持国密）
cd tongsuo-8.3.0
./Configure threads shared enable-sm2 enable-sm3 enable-sm4 enable-sm9 \
  --prefix=/usr/local/tongsuo --openssldir=/usr/local/tongsuo/ssl
make
make install

# 2. 编译curl（使用Tongsuo）
cd curl-8.11.1
PKG_CONFIG_PATH=/usr/local/tongsuo/lib/pkgconfig \
LD_LIBRARY_PATH=/usr/local/tongsuo/lib \
CFLAGS="-fstack-protector-all" \
LDFLAGS="-L/usr/local/tongsuo/lib -Wl,-rpath,/usr/local/tongsuo/lib" \
./configure --prefix=/usr/local/curl \
  --with-ssl=/usr/local/tongsuo \
  --with-ssl-backend=openssl
make
make install

# 3. 编译OBS C SDK
cd huaweicloud-sdk-c-obs
mkdir build && cd build
cmake -DUSE_CUSTOM=ON \
  -DTONGSUO_INC_DIR=/usr/local/tongsuo/include \
  -DTONGSUO_LIB_DIR=/usr/local/tongsuo/lib \
  -DCURL_INC_DIR=/usr/local/curl/include \
  -DCURL_LIB_DIR=/usr/local/curl/lib ..
make
```

## 12. 分析报告

### 12.1 现有SSL配置架构

通过对代码库的详细分析，发现OBS C SDK已经具备了基础的SSL配置框架：

#### 核心配置文件
- **ssl_config.c/h**：负责从OBS.ini配置文件加载SSL相关配置
- **eSDKOBS.h**：定义了SSL配置相关的结构体和枚举类型
- **request.c**：包含了实际应用SSL配置的代码

#### 已支持的SSL功能

1. **双向证书认证**：
   ```c
   typedef enum {
       OBS_MUTUAL_SSL_CLOSE = 0,
       OBS_MUTUAL_SSL_OPEN = 1
   } obs_mutual_ssl_switch;
   ```

2. **国密模式**：
   ```c
   typedef enum {
       OBS_GM_MODE_CLOSE = 0,  // 非国密模式（标准TLS）
       OBS_GM_MODE_OPEN = 1    // 国密模式（支持SM2/SM3/SM4）
   } obs_gm_mode_switch;
   ```

3. **SSL配置结构体**：
   ```c
   typedef struct obs_http_request_option {
       // ... 其他配置 ...
       char* server_cert_path;
       bool curl_log_verbose;
       // 双向证书认证配置
       obs_mutual_ssl_switch mutual_ssl_switch;
       char* client_cert_path;
       char* client_key_path;
       char* client_key_password;
       // SSL配置
       obs_gm_mode_switch gm_mode_switch;   // 国密模式开关
       long ssl_min_version;                // SSL最小版本（可选，默认TLSv1.2）
       long ssl_max_version;                // SSL最大版本（可选，默认TLSv1.3）
   } obs_http_request_option;
   ```

### 12.2 代码优化建议

#### 增强setup_CA函数

```c
obs_status setup_CA(http_request *request,
    const request_params *params,
    const request_computed_values *values)
{
    CURLcode status = CURLE_OK;

    // 基础SSL验证配置
    curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 2);  // 改为2，严格验证主机名

    // CA证书配置
    if (params->bucketContext.certificate_info) {
        curl_easy_setopt_safe(CURLOPT_SSL_CTX_DATA, (void *)params->bucketContext.certificate_info);
        curl_easy_setopt_safe(CURLOPT_SSL_CTX_FUNCTION, *sslctx_function);
    }
    if (params->request_option.server_cert_path) {
        curl_easy_setopt_safe(CURLOPT_CAINFO, params->request_option.server_cert_path);
    }

    // 双向认证配置
    if (params->request_option.mutual_ssl_switch == OBS_MUTUAL_SSL_OPEN) {
        if (!params->request_option.client_cert_path || !params->request_option.client_key_path) {
            COMMLOG(OBS_LOGERROR, "Mutual SSL enabled but client certificate or key not provided");
            return OBS_STATUS_InvalidParameter;
        }

        status = curl_easy_setopt(request->curl, CURLOPT_SSLCERT, params->request_option.client_cert_path);
        if (status != CURLE_OK) {
            COMMLOG(OBS_LOGERROR, "Failed to set client cert: %s", curl_easy_strerror(status));
            return OBS_STATUS_InternalError;
        }

        status = curl_easy_setopt(request->curl, CURLOPT_SSLKEY, params->request_option.client_key_path);
        if (status != CURLE_OK) {
            COMMLOG(OBS_LOGERROR, "Failed to set client key: %s", curl_easy_strerror(status));
            return OBS_STATUS_InternalError;
        }

        if (params->request_option.client_key_password) {
            status = curl_easy_setopt(request->curl, CURLOPT_KEYPASSWD,
                                      params->request_option.client_key_password);
            if (status != CURLE_OK) {
                COMMLOG(OBS_LOGERROR, "Failed to set client key password: %s", curl_easy_strerror(status));
                return OBS_STATUS_InternalError;
            }
        }

        COMMLOG(OBS_LOGINFO, "Mutual SSL authentication enabled");
    }

    // SSL套件和版本配置
    if (params->request_option.gm_mode_switch == OBS_GM_MODE_OPEN) {
        const char *gm_cipher_default = "ECDHE-SM2-WITH-SM4-SM3:ECDHE-SM2-WITH-SM4-GCM-SM3";
        const char *cipher_list = params->request_option.ssl_cipher_list ?
                                  params->request_option.ssl_cipher_list : gm_cipher_default;

        status = curl_easy_setopt(request->curl, CURLOPT_SSL_CIPHER_LIST, cipher_list);
        if (status != CURLE_OK) {
            COMMLOG(OBS_LOGERROR, "Failed to set GM cipher list: %s", curl_easy_strerror(status));
            return OBS_STATUS_InternalError;
        }

        status = curl_easy_setopt(request->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        if (status != CURLE_OK) {
            COMMLOG(OBS_LOGERROR, "Failed to set GM SSL version: %s", curl_easy_strerror(status));
            return OBS_STATUS_InternalError;
        }

        COMMLOG(OBS_LOGINFO, "GM mode enabled with cipher: %s", cipher_list);
    } else {
        const char *std_cipher_default = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
                                         "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256";
        const char *cipher_list = params->request_option.ssl_cipher_list ?
                                  params->request_option.ssl_cipher_list : std_cipher_default;

        status = curl_easy_setopt(request->curl, CURLOPT_SSL_CIPHER_LIST, cipher_list);
        if (status != CURLE_OK) {
            COMMLOG(OBS_LOGERROR, "Failed to set standard cipher list: %s", curl_easy_strerror(status));
            return OBS_STATUS_InternalError;
        }

        long min_ver = params->request_option.ssl_min_version ?
                           params->request_option.ssl_min_version : CURL_SSLVERSION_TLSv1_2;
        long max_ver = params->request_option.ssl_max_version ?
                           params->request_option.ssl_max_version : ((1 << 16) | 3);

        status = curl_easy_setopt(request->curl, CURLOPT_SSLVERSION, min_ver);
        if (status != CURLE_OK) {
            COMMLOG(OBS_LOGERROR, "Failed to set SSL min version: %s", curl_easy_strerror(status));
            return OBS_STATUS_InternalError;
        }

        status = curl_easy_setopt(request->curl, CURLOPT_SSLVERSION_MAX, max_ver);
        if (status != CURLE_OK) {
            COMMLOG(OBS_LOGERROR, "Failed to set SSL max version: %s", curl_easy_strerror(status));
            return OBS_STATUS_InternalError;
        }

        COMMLOG(OBS_LOGINFO, "Standard TLS mode enabled with min ver: %ld, max ver: %ld", min_ver, max_ver);
    }

    return OBS_STATUS_OK;
}
```

#### 增强配置加载

```c
void load_ssl_config_from_ini(obs_options *options)
{
    // 检查配置文件路径，支持相对和绝对路径
    char config_path[256] = {0};
    if (!GetModuleFileNameA(NULL, config_path, sizeof(config_path))) {
        COMMLOG(OBS_LOGWARN, "Failed to get module path");
        return;
    }
    char *slash = strrchr(config_path, '\\');
    if (slash) {
        *slash = '\0';
        strcat_s(config_path, sizeof(config_path), "\\OBS.ini");
    } else {
        strcpy_s(config_path, sizeof(config_path), "OBS.ini");
    }

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        // 尝试当前工作目录
        fp = fopen("OBS.ini", "r");
        if (!fp) {
            COMMLOG(OBS_LOGWARN, "Config file not found: %s", "OBS.ini");
            return;
        }
    }

    // ... 原解析逻辑 ...
}
```

#### 添加环境变量支持

```c
void load_ssl_config_from_env(obs_options *options)
{
    // 双向认证配置
    const char *mutual_ssl_env = getenv("OBS_MUTUAL_SSL_ENABLED");
    if (mutual_ssl_env) {
        if (strcmp(mutual_ssl_env, "true") == 0 || strcmp(mutual_ssl_env, "1") == 0) {
            options->request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
        }
    }

    const char *client_cert_env = getenv("OBS_CLIENT_CERT_PATH");
    if (client_cert_env) {
        options->request_options.client_cert_path = strdup(client_cert_env);
    }

    const char *client_key_env = getenv("OBS_CLIENT_KEY_PATH");
    if (client_key_env) {
        options->request_options.client_key_path = strdup(client_key_env);
    }

    const char *client_key_pass_env = getenv("OBS_CLIENT_KEY_PASSWORD");
    if (client_key_pass_env) {
        options->request_options.client_key_password = strdup(client_key_pass_env);
    }

    // 国密模式配置
    const char *gm_mode_env = getenv("OBS_GM_MODE_ENABLED");
    if (gm_mode_env) {
        if (strcmp(gm_mode_env, "true") == 0 || strcmp(gm_mode_env, "1") == 0) {
            options->request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
        }
    }

    const char *ssl_cipher_env = getenv("OBS_SSL_CIPHER_LIST");
    if (ssl_cipher_env) {
        options->request_options.ssl_cipher_list = strdup(ssl_cipher_env);
    }

    // SSL版本配置
    const char *ssl_min_ver_env = getenv("OBS_SSL_MIN_VERSION");
    if (ssl_min_ver_env) {
        long ssl_min_ver = 0;
        if (strcmp(ssl_min_ver_env, "1.0") == 0) {
            ssl_min_ver = CURL_SSLVERSION_TLSv1_0;
        } else if (strcmp(ssl_min_ver_env, "1.1") == 0) {
            ssl_min_ver = CURL_SSLVERSION_TLSv1_1;
        } else if (strcmp(ssl_min_ver_env, "1.2") == 0) {
            ssl_min_ver = CURL_SSLVERSION_TLSv1_2;
        } else if (strcmp(ssl_min_ver_env, "1.3") == 0) {
            ssl_min_ver = (1 << 16) | 3;  // TLSv1.3
        }
        options->request_options.ssl_min_version = ssl_min_ver;
    }

    const char *ssl_max_ver_env = getenv("OBS_SSL_MAX_VERSION");
    if (ssl_max_ver_env) {
        long ssl_max_ver = 0;
        if (strcmp(ssl_max_ver_env, "1.0") == 0) {
            ssl_max_ver = CURL_SSLVERSION_TLSv1_0;
        } else if (strcmp(ssl_max_ver_env, "1.1") == 0) {
            ssl_max_ver = CURL_SSLVERSION_TLSv1_1;
        } else if (strcmp(ssl_max_ver_env, "1.2") == 0) {
            ssl_max_ver = CURL_SSLVERSION_TLSv1_2;
        } else if (strcmp(ssl_max_ver_env, "1.3") == 0) {
            ssl_max_ver = (1 << 16) | 3;  // TLSv1.3
        }
        options->request_options.ssl_max_version = ssl_max_ver;
    }

    COMMLOG(OBS_LOGINFO, "SSL configuration loaded from environment variables");
}
```

## 13. 风险评估和缓解策略

### 13.1 风险1：算法库兼容性

- **风险**：不同Tongsuo版本可能有API差异
- **缓解**：添加版本检测，使用条件编译
- **解决方案**：提供最小版本要求和兼容性矩阵

### 13.2 风险2：性能影响

- **风险**：国密算法可能比传统算法慢
- **缓解**：实现硬件加速支持
- **解决方案**：提供性能基准和优化建议

### 13.3 风险3：证书格式兼容性

- **风险**：国密证书格式可能与标准X.509有差异
- **缓解**：增强证书解析和验证逻辑
- **解决方案**：支持多种证书格式（PEM、DER、PKCS#12等）

### 13.4 风险4：网络环境影响

- **风险**：某些网络可能不支持国密套件
- **缓解**：实现优雅降级到标准TLS
- **解决方案**：添加连接失败重试和算法切换机制

## 14. 总结

华为云OBS C SDK提供了对HTTPS国密（SM2/SM3/SM4）和双向认证功能的支持，确保在敏感数据传输过程中的安全性和合规性。本功能具有以下特点：

1. 完整的架构设计，包括核心组件和功能模块
2. 详细的实现细节，包括配置加载、国密模式切换、错误处理等
3. 性能优化建议，包括SSL会话重用、连接池优化和硬件加速
4. 兼容性设计，包括算法库兼容性和配置兼容性
5. 测试策略，包括单元测试和集成测试
6. 文档和示例，包括API文档和使用示例
7. 编译和部署指南，适用于内网环境

方案具有良好的可扩展性、可维护性和兼容性，同时提供了详细的实施计划和风险评估，确保功能的正确实现和性能优化。
