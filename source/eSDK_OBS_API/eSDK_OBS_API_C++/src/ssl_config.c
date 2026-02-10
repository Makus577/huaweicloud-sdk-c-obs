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
**********************************************************************************
*/
#include "ssl_config.h"
#include "log.h"
#include <stdio.h>
#include <string.h>
#include "securec.h"
#include <stdlib.h>
#include <ctype.h>

#define MAX_CONFIG_LINE 256
#define CONFIG_FILE "OBS.ini"

// 辅助函数：去除字符串首尾的空白字符
static char *trim_string(char *str)
{
    if (!str)
        return NULL;

    // 去除前导空白字符
    while (isspace((unsigned char)*str))
        str++;

    if (*str == '\0')  // 字符串全是空白字符
        return str;

    // 去除尾随空白字符
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    // 写入字符串结束符
    *(end + 1) = '\0';

    return str;
}

// 辅助函数：解析配置项字符串值
static void parse_config_string_value(const char *line, char *buffer, size_t buffer_size)
{
    char *value = strchr(line, '=');
    if (value && *(value + 1))
    {
        value++;
        size_t len = strlen(value);
        if (len > 0 && (value[len - 1] == '\n' || value[len - 1] == '\r'))
        {
            value[len - 1] = '\0';
            len--;
        }
        if (len > 0 && len < buffer_size)
        {
            char temp_value[MAX_CONFIG_LINE] = {0};
            strncpy_s(temp_value, sizeof(temp_value), value, len);
            char *trimmed_value = trim_string(temp_value);
            errno_t err = strcpy_s(buffer, buffer_size, trimmed_value, strlen(trimmed_value));
            if (err != EOK)
            {
                COMMLOG(OBS_LOGERROR, "%s(%d): strcpy_s failed with error %d!", __FUNCTION__, __LINE__, err);
            }
            else if (strlen(buffer) > 0)
            {
                COMMLOG(OBS_LOGDEBUG, "%s Parsed config value: %s", __FUNCTION__, buffer);
            }
        }
        else
        {
            COMMLOG(OBS_LOGWARN, "%s Config value length %zu exceeds buffer size %zu", __FUNCTION__, len, buffer_size);
        }
    }
}

// 辅助函数：分配并复制字符串
static void alloc_copy_string(const char *src, char **dest)
{
    if (src && src[0] != '\0')
    {
        size_t len = strlen(src);
        *dest = (char *)malloc(len + 1);
        if (*dest)
        {
            errno_t err = strcpy_s(*dest, len + 1, src, len);
            if (err != EOK)
            {
                COMMLOG(OBS_LOGERROR, "%s(%d): strcpy_s failed with error %d!", __FUNCTION__, __LINE__, err);
                free(*dest);
                *dest = NULL;
            }
            else
            {
                COMMLOG(OBS_LOGINFO, "%s Allocated and copied string: %s", __FUNCTION__, src);
            }
        }
        else
        {
            COMMLOG(OBS_LOGERROR, "%s Failed to allocate memory for string: %s", __FUNCTION__, src);
        }
    }
}

// 辅助函数：解析SSL版本
static void parse_ssl_version(const char *ver_str, long *dest, long default_value)
{
    if (ver_str && ver_str[0] != '\0')
    {
        char temp_ver[MAX_CONFIG_LINE] = {0};
        strncpy_s(temp_ver, sizeof(temp_ver), ver_str, strlen(ver_str));
        char *trimmed_ver = trim_string(temp_ver);

        if (strcmp(trimmed_ver, "1.0") == 0)
            *dest = CURL_SSLVERSION_TLSv1_0;
        else if (strcmp(trimmed_ver, "1.1") == 0)
            *dest = CURL_SSLVERSION_TLSv1_1;
        else if (strcmp(trimmed_ver, "1.2") == 0)
            *dest = CURL_SSLVERSION_TLSv1_2;
        else if (strcmp(trimmed_ver, "1.3") == 0)
            *dest = (1 << 16) | 3;  // CURL_SSLVERSION_TLSv1_3
        else
        {
            COMMLOG(OBS_LOGWARN, "%s Invalid SSL version: %s, using default %ld", __FUNCTION__, trimmed_ver, default_value);
            *dest = default_value;
            return;
        }

        COMMLOG(OBS_LOGINFO, "%s SSL version parsed: %s", __FUNCTION__, trimmed_ver);
    }
    else
    {
        *dest = default_value;
        COMMLOG(OBS_LOGDEBUG, "%s No SSL version specified, using default %ld", __FUNCTION__, default_value);
    }
}

// 配置验证函数
static int validate_ssl_config(const obs_http_request_option *config)
{
    if (config == NULL)
    {
        COMMLOG(OBS_LOGERROR, "%s SSL configuration is NULL", __FUNCTION__);
        return -1;
    }

    // 验证双向认证配置
    if (config->mutual_ssl_switch == OBS_MUTUAL_SSL_OPEN)
    {
        if (!config->client_cert_path || strlen(config->client_cert_path) == 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Mutual SSL enabled but client certificate path not specified", __FUNCTION__);
            return -2;
        }

        if (!config->client_key_path || strlen(config->client_key_path) == 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Mutual SSL enabled but client key path not specified", __FUNCTION__);
            return -3;
        }

        // 检查证书文件是否存在且可读
        if (access(config->client_cert_path, R_OK) != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Client certificate file not found or unreadable: %s", __FUNCTION__, config->client_cert_path);
            return -4;
        }

        // 检查密钥文件是否存在且可读
        if (access(config->client_key_path, R_OK) != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Client key file not found or unreadable: %s", __FUNCTION__, config->client_key_path);
            return -5;
        }
    }

    // 验证国密模式配置
    if (config->gm_mode_switch == OBS_GM_MODE_OPEN)
    {
        // 国密模式建议使用TLSv1.2
        if (config->ssl_min_version > CURL_SSLVERSION_TLSv1_2 ||
            config->ssl_max_version < CURL_SSLVERSION_TLSv1_2)
        {
            COMMLOG(OBS_LOGWARN, "%s GM mode is enabled but SSL version range %ld to %ld is not compatible", __FUNCTION__, config->ssl_min_version, config->ssl_max_version);
        }

        // 验证国密模式下的SSL密码套件配置
        if (config->ssl_cipher_list)
        {
            // 检查是否包含国密密码套件
            if (strstr(config->ssl_cipher_list, "SM") == NULL && strstr(config->ssl_cipher_list, "sm") == NULL)
            {
                COMMLOG(OBS_LOGWARN, "%s GM mode is enabled but cipher list does not contain SM algorithms: %s", __FUNCTION__, config->ssl_cipher_list);
            }
        }
    }

    // 验证SSL版本范围配置
    if (config->ssl_min_version > config->ssl_max_version)
    {
        COMMLOG(OBS_LOGERROR, "%s SSL minimum version (%ld) is greater than maximum version (%ld)", __FUNCTION__, config->ssl_min_version, config->ssl_max_version);
        return -6;
    }

    // 验证服务器证书路径（如果提供）
    if (config->server_cert_path && strlen(config->server_cert_path) > 0)
    {
        if (access(config->server_cert_path, R_OK) != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Server certificate file not found or unreadable: %s", __FUNCTION__, config->server_cert_path);
            return -7;
        }
    }

    return 0;
}

// 从环境变量加载SSL配置
static void load_ssl_config_from_env(obs_options *options)
{
    // 双向认证配置
    const char *mutual_ssl_env = getenv("OBS_MUTUAL_SSL_ENABLED");
    if (mutual_ssl_env)
    {
        if (strcmp(mutual_ssl_env, "true") == 0 || strcmp(mutual_ssl_env, "1") == 0)
        {
            options->request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
            COMMLOG(OBS_LOGINFO, "%s Mutual SSL enabled from environment variable", __FUNCTION__);
        }
        else if (strcmp(mutual_ssl_env, "false") == 0 || strcmp(mutual_ssl_env, "0") == 0)
        {
            options->request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
            COMMLOG(OBS_LOGINFO, "%s Mutual SSL disabled from environment variable", __FUNCTION__);
        }
    }

    const char *client_cert_env = getenv("OBS_CLIENT_CERT_PATH");
    if (client_cert_env)
    {
        alloc_copy_string(client_cert_env, &options->request_options.client_cert_path);
    }

    const char *client_key_env = getenv("OBS_CLIENT_KEY_PATH");
    if (client_key_env)
    {
        alloc_copy_string(client_key_env, &options->request_options.client_key_path);
    }

    const char *client_key_pass_env = getenv("OBS_CLIENT_KEY_PASSWORD");
    if (client_key_pass_env)
    {
        alloc_copy_string(client_key_pass_env, &options->request_options.client_key_password);
    }

    // 国密模式配置
    const char *gm_mode_env = getenv("OBS_GM_MODE_ENABLED");
    if (gm_mode_env)
    {
        if (strcmp(gm_mode_env, "true") == 0 || strcmp(gm_mode_env, "1") == 0)
        {
            options->request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
            COMMLOG(OBS_LOGINFO, "%s GM mode enabled from environment variable", __FUNCTION__);
        }
        else if (strcmp(gm_mode_env, "false") == 0 || strcmp(gm_mode_env, "0") == 0)
        {
            options->request_options.gm_mode_switch = OBS_GM_MODE_CLOSE;
            COMMLOG(OBS_LOGINFO, "%s GM mode disabled from environment variable", __FUNCTION__);
        }
    }

    const char *ssl_cipher_env = getenv("OBS_SSL_CIPHER_LIST");
    if (ssl_cipher_env)
    {
        alloc_copy_string(ssl_cipher_env, &options->request_options.ssl_cipher_list);
    }

    // SSL版本配置
    const char *ssl_min_ver_env = getenv("OBS_SSL_MIN_VERSION");
    if (ssl_min_ver_env)
    {
        parse_ssl_version(ssl_min_ver_env, &options->request_options.ssl_min_version, CURL_SSLVERSION_TLSv1_2);
    }

    const char *ssl_max_ver_env = getenv("OBS_SSL_MAX_VERSION");
    if (ssl_max_ver_env)
    {
        parse_ssl_version(ssl_max_ver_env, &options->request_options.ssl_max_version, (1 << 16) | 3);
    }
}

// 初始化HTTP请求配置选项
void init_http_request_option(obs_http_request_option *options)
{
    if (!options)
    {
        COMMLOG(OBS_LOGERROR, "%s Options parameter is NULL", __FUNCTION__);
        return;
    }

    memset(options, 0, sizeof(obs_http_request_option));

    // 初始化默认值
    options->speed_limit = 0;
    options->speed_time = 0;
    options->connect_time = 30;
    options->max_connected_time = 60;
    options->keep_alive = true;
    options->keep_idle = 60;
    options->keep_intvl = 60;
    options->proxy_host = NULL;
    options->proxy_auth = NULL;
    options->ssl_cipher_list = NULL;
    options->forbid_reuse_tcp = false;
    options->curl_max_connects = -1;
    options->http2_switch = OBS_HTTP2_CLOSE;
    options->bbr_switch = OBS_BBR_CLOSE;
    options->auth_switch = OBS_NEGOTIATION_TYPE;
    options->buffer_size = 0;
    options->server_cert_path = NULL;
    options->curl_log_verbose = false;
    options->mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    options->client_cert_path = NULL;
    options->client_key_path = NULL;
    options->client_key_password = NULL;
    options->gm_mode_switch = OBS_GM_MODE_CLOSE;
    options->ssl_min_version = CURL_SSLVERSION_TLSv1_2;
    options->ssl_max_version = (1 << 16) | 3; // TLSv1.3

    COMMLOG(OBS_LOGDEBUG, "%s HTTP request options initialized with default values", __FUNCTION__);
}

// 检查配置文件是否存在
static int file_exists(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (fp)
    {
        fclose(fp);
        return 1;
    }
    return 0;
}

// 获取配置文件路径
static char *get_config_file_path(void)
{
    // 首先尝试当前工作目录
    if (file_exists(CONFIG_FILE))
    {
        COMMLOG(OBS_LOGDEBUG, "%s Config file found in current working directory", __FUNCTION__);
        return strdup(CONFIG_FILE);
    }

    // 在Windows系统上，尝试获取模块路径
#ifdef WIN32
    char module_path[MAX_CONFIG_LINE] = {0};
    if (GetModuleFileNameA(NULL, module_path, sizeof(module_path)))
    {
        char *slash = strrchr(module_path, '\\');
        if (slash)
        {
            *slash = '\0';
            char config_path[MAX_CONFIG_LINE] = {0};
            sprintf_s(config_path, sizeof(config_path), "%s\\OBS.ini", module_path);
            if (file_exists(config_path))
            {
                COMMLOG(OBS_LOGDEBUG, "%s Config file found in module directory", __FUNCTION__);
                return strdup(config_path);
            }
        }
    }
#else
    // 在Linux/Unix系统上，尝试常见位置
    const char *config_dirs[] = {
        "/etc",
        "/etc/obs",
        "/usr/local/etc",
        "/usr/local/etc/obs"
    };

    for (int i = 0; i < sizeof(config_dirs) / sizeof(config_dirs[0]); i++)
    {
        char config_path[MAX_CONFIG_LINE] = {0};
        sprintf_s(config_path, sizeof(config_path), "%s/OBS.ini", config_dirs[i]);
        if (file_exists(config_path))
        {
            COMMLOG(OBS_LOGDEBUG, "%s Config file found in %s", __FUNCTION__, config_path);
            return strdup(config_path);
        }
    }
#endif

    COMMLOG(OBS_LOGWARN, "%s Config file not found in any standard locations", __FUNCTION__);
    return NULL;
}

void load_ssl_config_from_ini(obs_options *options)
{
    if (!options)
    {
        COMMLOG(OBS_LOGERROR, "%s Options parameter is NULL", __FUNCTION__);
        return;
    }

    // 获取配置文件路径
    char *config_path = get_config_file_path();
    if (!config_path)
    {
        // 尝试默认位置
        if (!file_exists(CONFIG_FILE))
        {
            COMMLOG(OBS_LOGWARN, "%s Config file not found: %s", __FUNCTION__, CONFIG_FILE);
            load_ssl_config_from_env(options);
            return;
        }
        config_path = strdup(CONFIG_FILE);
    }

    FILE *fp = fopen(config_path, "r");
    if (!fp)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to open config file: %s", __FUNCTION__, config_path);
        free(config_path);
        load_ssl_config_from_env(options);
        return;
    }

    COMMLOG(OBS_LOGINFO, "%s Loading SSL configuration from: %s", __FUNCTION__, config_path);

    char line[MAX_CONFIG_LINE] = {0};
    int in_ssl_config = 0;

    char mutual_ssl_str[16] = {0};
    char client_cert_path[1024] = {0};
    char client_key_path[1024] = {0};
    char client_key_password[64] = {0};
    char gm_mode_str[16] = {0};
    char ssl_cipher_list[512] = {0};
    char ssl_min_ver_str[16] = {0};
    char ssl_max_ver_str[16] = {0};

    int line_number = 0;
    while (fgets(line, sizeof(line), fp))
    {
        line_number++;
        // 跳过空行和注释
        if (line[0] == '\n' || line[0] == '#' || line[0] == ';' || line[0] == '\r')
        {
            continue;
        }

        // 检测 [SSLConfig] 段
        if (strstr(line, "[SSLConfig]"))
        {
            in_ssl_config = 1;
            COMMLOG(OBS_LOGDEBUG, "%s Found SSLConfig section at line %d", __FUNCTION__, line_number);
            continue;
        }
        else if (line[0] == '[')
        {
            in_ssl_config = 0;
            continue;
        }

        if (!in_ssl_config)
        {
            continue;
        }

        // 解析配置项
        if (strstr(line, "MutualSSLEnabled"))
        {
            parse_config_string_value(line, mutual_ssl_str, sizeof(mutual_ssl_str));
            COMMLOG(OBS_LOGDEBUG, "%s Parsed MutualSSLEnabled: %s", __FUNCTION__, mutual_ssl_str);
        }
        else if (strstr(line, "ClientCertPath"))
        {
            parse_config_string_value(line, client_cert_path, sizeof(client_cert_path));
            COMMLOG(OBS_LOGDEBUG, "%s Parsed ClientCertPath: %s", __FUNCTION__, client_cert_path);
        }
        else if (strstr(line, "ClientKeyPath"))
        {
            parse_config_string_value(line, client_key_path, sizeof(client_key_path));
            COMMLOG(OBS_LOGDEBUG, "%s Parsed ClientKeyPath: %s", __FUNCTION__, client_key_path);
        }
        else if (strstr(line, "ClientKeyPassword"))
        {
            parse_config_string_value(line, client_key_password, sizeof(client_key_password));
            COMMLOG(OBS_LOGDEBUG, "%s Parsed ClientKeyPassword: %s", __FUNCTION__, client_key_password);
        }
        else if (strstr(line, "GMModeEnabled"))
        {
            parse_config_string_value(line, gm_mode_str, sizeof(gm_mode_str));
            COMMLOG(OBS_LOGDEBUG, "%s Parsed GMModeEnabled: %s", __FUNCTION__, gm_mode_str);
        }
        else if (strstr(line, "CipherList"))
        {
            parse_config_string_value(line, ssl_cipher_list, sizeof(ssl_cipher_list));
            COMMLOG(OBS_LOGDEBUG, "%s Parsed CipherList: %s", __FUNCTION__, ssl_cipher_list);
        }
        else if (strstr(line, "SSLMinVersion"))
        {
            parse_config_string_value(line, ssl_min_ver_str, sizeof(ssl_min_ver_str));
            COMMLOG(OBS_LOGDEBUG, "%s Parsed SSLMinVersion: %s", __FUNCTION__, ssl_min_ver_str);
        }
        else if (strstr(line, "SSLMaxVersion"))
        {
            parse_config_string_value(line, ssl_max_ver_str, sizeof(ssl_max_ver_str));
            COMMLOG(OBS_LOGDEBUG, "%s Parsed SSLMaxVersion: %s", __FUNCTION__, ssl_max_ver_str);
        }
    }

    fclose(fp);
    free(config_path);

    // 应用双向SSL配置
    if (strcmp(mutual_ssl_str, "true") == 0)
    {
        options->request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_OPEN;
        COMMLOG(OBS_LOGINFO, "%s Mutual SSL enabled from config", __FUNCTION__);
    }
    else if (strcmp(mutual_ssl_str, "false") == 0)
    {
        options->request_options.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
        COMMLOG(OBS_LOGINFO, "%s Mutual SSL disabled from config", __FUNCTION__);
    }

    alloc_copy_string(client_cert_path, &options->request_options.client_cert_path);
    alloc_copy_string(client_key_path, &options->request_options.client_key_path);
    alloc_copy_string(client_key_password, &options->request_options.client_key_password);

    // 应用国密模式配置
    if (strcmp(gm_mode_str, "true") == 0)
    {
        options->request_options.gm_mode_switch = OBS_GM_MODE_OPEN;
        COMMLOG(OBS_LOGINFO, "%s GM mode enabled from config", __FUNCTION__);
    }
    else if (strcmp(gm_mode_str, "false") == 0)
    {
        options->request_options.gm_mode_switch = OBS_GM_MODE_CLOSE;
        COMMLOG(OBS_LOGINFO, "%s GM mode disabled from config", __FUNCTION__);
    }

    alloc_copy_string(ssl_cipher_list, &options->request_options.ssl_cipher_list);

    // 应用SSL版本配置
    parse_ssl_version(ssl_min_ver_str, &options->request_options.ssl_min_version, CURL_SSLVERSION_TLSv1_2);
    parse_ssl_version(ssl_max_ver_str, &options->request_options.ssl_max_version, (1 << 16) | 3);

    // 应用环境变量配置（环境变量优先级高于配置文件）
    load_ssl_config_from_env(options);

    // 验证配置
    int validation_result = validate_ssl_config(&options->request_options);
    if (validation_result != 0)
    {
        COMMLOG(OBS_LOGERROR, "%s SSL configuration validation failed with error code: %d", __FUNCTION__, validation_result);
    }
    else
    {
        COMMLOG(OBS_LOGDEBUG, "%s SSL configuration validation passed", __FUNCTION__);
    }
}
