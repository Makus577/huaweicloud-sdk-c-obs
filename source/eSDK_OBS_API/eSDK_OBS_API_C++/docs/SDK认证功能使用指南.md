# SDK认证功能使用指南

## 1. 功能概述

本SDK支持四种认证方式的组合配置，满足不同场景的安全需求：

| 认证模式 | gm_mode_switch | mutual_ssl_switch | 说明 |
|---------|---------------|------------------|------|
| 标准TLS单向认证 | 0 | 0 | 验证服务器证书，默认安全配置 |
| 标准TLS双向认证 | 0 | 1 | 双向证书验证，安全性更高 |
| 国密单向认证 | 1 | 0 | 国密算法验证服务器证书 |
| 国密双向认证 | 1 | 1 | 国密算法+双向证书验证 |

**核心参数说明：**
- `gm_mode_switch`：国密模式开关（0=标准TLS，1=国密模式）
- `mutual_ssl_switch`：双向认证开关（0=单向认证，1=双向认证）

## 2. 快速配置

### 2.1 标准TLS单向认证（默认配置）

```c
obs_options options;
obs_response_options response_options;
obs_init_options(&options, OBS_IOHTTPS);

options.socket_options.ssl_config.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
options.socket_options.ssl_config.gm_mode_switch = OBS_GM_MODE_CLOSE;
options.socket_options.ssl_config.verify_hostname = 1;  // 开启主机名验证
```

### 2.2 标准TLS双向认证

```c
obs_init_options(&options, OBS_IOHTTPS);

options.socket_options.ssl_config.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
options.socket_options.ssl_config.client_cert_path = "/path/to/client.crt";
options.socket_options.ssl_config.client_key_path = "/path/to/client.key";
options.socket_options.ssl_config.client_key_password = "your_password";  // 可选
options.socket_options.ssl_config.gm_mode_switch = OBS_GM_MODE_CLOSE;
```

### 2.3 国密单向认证

```c
obs_init_options(&options, OBS_IOHTTPS);

options.socket_options.ssl_config.gm_mode_switch = OBS_GM_MODE_OPEN;
options.socket_options.ssl_config.verify_hostname = 1;
options.socket_options.ssl_config.ssl_min_version = OBS_SSL_VERSION_TLSv1_2;
options.socket_options.ssl_config.ssl_max_version = OBS_SSL_VERSION_TLSv1_2;  // 国密强制TLSv1.2
```

### 2.4 国密双向认证

```c
obs_init_options(&options, OBS_IOHTTPS);

options.socket_options.ssl_config.gm_mode_switch = OBS_GM_MODE_OPEN;
options.socket_options.ssl_config.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
options.socket_options.ssl_config.client_cert_path = "/path/to/gm_client.crt";
options.socket_options.ssl_config.client_key_path = "/path/to/gm_client.key";
options.socket_options.ssl_config.ssl_min_version = OBS_SSL_VERSION_TLSv1_2;
options.socket_options.ssl_config.ssl_max_version = OBS_SSL_VERSION_TLSv1_2;
```

## 3. 配置参数说明

### 3.1 认证模式参数

| 参数名 | 类型 | 可选值 | 说明 |
|-------|------|-------|------|
| gm_mode_switch | int | 0=标准TLS, 1=国密模式 | 选择使用国际标准TLS或国密算法 |
| mutual_ssl_switch | int | 0=单向认证, 1=双向认证 | 是否启用客户端证书 |

### 3.2 双向认证参数

| 参数名 | 类型 | 说明 |
|-------|------|------|
| client_cert_path | string | 客户端证书路径（PEM格式） |
| client_key_path | string | 客户端私钥路径 |
| client_key_password | string | 私钥密码（如有） |

### 3.3 安全验证参数

| 参数名 | 类型 | 说明 |
|-------|------|------|
| verify_hostname | int | 是否验证服务器证书主机名（建议开启） |
| server_cert_path | string | 自定义CA证书路径（可选） |

### 3.4 TLS版本参数

| 参数名 | 类型 | 说明 |
|-------|------|------|
| ssl_min_version | int | 最小TLS版本 |
| ssl_max_version | int | 最大TLS版本 |

**说明：**
- 标准TLS模式支持TLS v1.0 ~ v1.3
- 国密模式强制使用TLS v1.2

## 4. 配置组合速查表

| 组合 | gm_mode_switch | mutual_ssl_switch | 备注 |
|-----|---------------|------------------|------|
| 标准单向 | 0 | 0 | 默认配置 |
| 标准双向 | 0 | 1 | 需提供客户端证书 |
| 国密单向 | 1 | 0 | TLS版本固定为1.2 |
| 国密双向 | 1 | 1 | TLS版本固定为1.2，需国密证书 |

## 5. 常见问题

### Q1: 双向认证需要哪些文件？
需要客户端证书（.crt或.pem）和客户端私钥（.key），均需为PEM格式。

### Q2: 国密模式为何强制TLS v1.2？
国密算法套件（如ECDHE-SM2-WITH-SM4-SM3）需要TLS v1.2支持，因此SDK自动锁定为TLS v1.2。

### Q3: 如何验证配置是否正确？
调用API前，确保：
- 证书文件路径存在且可读
- 私钥文件路径存在且可读
- 密码（如有）正确

### Q4: 生产环境建议配置？
- 建议开启 `verify_hostname = 1`
- 优先使用双向认证
- 限制TLS最低版本为v1.2

## 6. 编译说明

### 6.1 标准TLS模式编译

```bash
cd source/eSDK_OBS_API/eSDK_OBS_API_C++
cmake ..
make -j
```

### 6.2 国密模式编译（Tongsuo）

国密模式需要Tongsuo（中国密码）库支持，编译步骤如下：

#### 步骤1：编译Tongsuo

```bash
git clone https://github.com/Tongsuo-Project/Tongsuo
cd Tongsuo
./config --prefix=/opt/tongsuo enable-ntls
make -j && make install
```

**关键配置：**
- `--prefix=/opt/tongsuo`：安装路径
- `enable-ntls`：启用国密TLCP协议支持

#### 步骤2：编译curl（国密libcurl）

```bash
git clone https://github.com/Tongsuo-Project/curl.git
cd curl
git apply tongsuo.patch              # 应用铜锁补丁
autoreconf -fi                       # 重新生成configure

# 关键：设置rpath确保运行时能找到Tongsuo库
LDFLAGS=-Wl,-rpath=/opt/tongsuo/lib64 \
./configure --enable-warnings --enable-werror \
            --with-openssl=/opt/tongsuo

make -j && make install
```

**关键要点：**
- 必须先构建Tongsuo，curl依赖Tongsuo提供国密功能
- `LDFLAGS=-Wl,-rpath=/opt/tongsuo/lib64`：避免运行时找不到libcrypto等库
- `--with-openssl=/opt/tongsuo`：指定使用Tongsuo而非系统OpenSSL

#### 步骤3：编译OBS SDK（国密模式）

```bash
cd source/eSDK_OBS_API/eSDK_OBS_API_C++
cmake -DOBS_ENABLE_GM_SUPPORT=ON ..
make -j
```

**说明：**
- `OBS_ENABLE_GM_SUPPORT=ON`：启用国密支持开关
- 国密模式强制TLS v1.2（国密算法套件要求）
