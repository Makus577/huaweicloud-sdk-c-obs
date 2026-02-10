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

// 配置来源枚举
typedef enum {
    CONFIG_SOURCE_DEFAULT,    // 默认配置
    CONFIG_SOURCE_INI,        // 配置文件
    CONFIG_SOURCE_ENV,        // 环境变量
    CONFIG_SOURCE_API         // API设置
} config_source_t;

// 配置项定义
typedef struct {
    const char *name;         // 配置项名称
    config_source_t source;   // 配置来源
    int integer_value;        // 整数值
    const char *string_value; // 字符串值
} config_item_t;

// 配置上下文
typedef struct {
    obs_http_request_option config;
    int is_initialized;
    config_source_t source_map[OBS_CONFIG_MAX_ITEMS]; // 每个配置项的来源
} config_context_t;

// 全局配置上下文
static config_context_t g_config_context = {0};

// 配置项映射表
static const char *config_item_names[] = {
    "speed_limit",
    "speed_time",
    "connect_time",
    "max_connected_time",
    "keep_alive",
    "keep_idle",
    "keep_intvl",
    "proxy_host",
    "proxy_auth",
    "ssl_cipher_list",
    "forbid_reuse_tcp",
    "curl_max_connects",
    "http2_switch",
    "bbr_switch",
    "auth_switch",
    "buffer_size",
    "server_cert_path",
    "curl_log_verbose",
    "mutual_ssl_switch",
    "client_cert_path",
    "client_key_path",
    "client_key_password",
    #if OBS_ENABLE_GM_SUPPORT
    "gm_mode_switch",
    #endif
    "ssl_min_version",
    "ssl_max_version",
    "ocsp_stapling",
    "certificate_pin",
    "certificate_pin_count",
    "verify_hostname",
    "enable_session_tickets",
    "ssl_session_cache_timeout"
};

// 配置变更回调链表
typedef struct callback_node {
    config_change_callback_t callback;
    struct callback_node *next;
} callback_node_t;

static callback_node_t *g_callback_list = NULL;

// 设置配置项值（内部函数）
static int config_set_internal(obs_config_item_t item, const char *value, config_source_t source)
{
    if (item < 0 || item >= OBS_CONFIG_MAX_ITEMS) {
        COMMLOG(OBS_LOGERROR, "Invalid config item: %d", item);
        return -1;
    }

    // 如果当前配置来源优先级更高，则不更新
    if (g_config_context.source_map[item] > source) {
        COMMLOG(OBS_LOGDEBUG, "Config item %s already set from higher priority source",
                config_item_names[item]);
        return 0;
    }

    // 更新配置
    switch (item) {
        case OBS_CONFIG_SPEED_LIMIT:
            g_config_context.config.speed_limit = atoi(value);
            break;
        case OBS_CONFIG_SPEED_TIME:
            g_config_context.config.speed_time = atoi(value);
            break;
        case OBS_CONFIG_CONNECT_TIME:
            g_config_context.config.connect_time = atoi(value);
            break;
        case OBS_CONFIG_MAX_CONNECTED_TIME:
            g_config_context.config.max_connected_time = atoi(value);
            break;
        case OBS_CONFIG_KEEP_ALIVE:
            g_config_context.config.keep_alive = (strcmp(value, "true") == 0 || atoi(value) != 0);
            break;
        case OBS_CONFIG_KEEP_IDLE:
            g_config_context.config.keep_idle = atoi(value);
            break;
        case OBS_CONFIG_KEEP_INTVL:
            g_config_context.config.keep_intvl = atoi(value);
            break;
        case OBS_CONFIG_PROXY_HOST:
            if (g_config_context.config.proxy_host) {
                free(g_config_context.config.proxy_host);
            }
            g_config_context.config.proxy_host = strdup(value);
            break;
        case OBS_CONFIG_PROXY_AUTH:
            if (g_config_context.config.proxy_auth) {
                free(g_config_context.config.proxy_auth);
            }
            g_config_context.config.proxy_auth = strdup(value);
            break;
        case OBS_CONFIG_SSL_CIPHER_LIST:
            if (g_config_context.config.ssl_cipher_list) {
                free(g_config_context.config.ssl_cipher_list);
            }
            g_config_context.config.ssl_cipher_list = strdup(value);
            break;
        case OBS_CONFIG_FORBID_REUSE_TCP:
            g_config_context.config.forbid_reuse_tcp = (strcmp(value, "true") == 0 || atoi(value) != 0);
            break;
        case OBS_CONFIG_CURL_MAX_CONNECTS:
            g_config_context.config.curl_max_connects = atoi(value);
            break;
        case OBS_CONFIG_HTTP2_SWITCH:
            g_config_context.config.http2_switch = atoi(value);
            break;
        case OBS_CONFIG_BBR_SWITCH:
            g_config_context.config.bbr_switch = atoi(value);
            break;
        case OBS_CONFIG_AUTH_SWITCH:
            g_config_context.config.auth_switch = atoi(value);
            break;
        case OBS_CONFIG_BUFFER_SIZE:
            g_config_context.config.buffer_size = atoi(value);
            break;
        case OBS_CONFIG_SERVER_CERT_PATH:
            if (g_config_context.config.server_cert_path) {
                free(g_config_context.config.server_cert_path);
            }
            g_config_context.config.server_cert_path = strdup(value);
            break;
        case OBS_CONFIG_CURL_LOG_VERBOSE:
            g_config_context.config.curl_log_verbose = (strcmp(value, "true") == 0 || atoi(value) != 0);
            break;
        case OBS_CONFIG_MUTUAL_SSL_SWITCH:
            g_config_context.config.mutual_ssl_switch = atoi(value);
            break;
        case OBS_CONFIG_CLIENT_CERT_PATH:
            if (g_config_context.config.client_cert_path) {
                free(g_config_context.config.client_cert_path);
            }
            g_config_context.config.client_cert_path = strdup(value);
            break;
        case OBS_CONFIG_CLIENT_KEY_PATH:
            if (g_config_context.config.client_key_path) {
                free(g_config_context.config.client_key_path);
            }
            g_config_context.config.client_key_path = strdup(value);
            break;
        case OBS_CONFIG_CLIENT_KEY_PASSWORD:
            if (g_config_context.config.client_key_password) {
                free(g_config_context.config.client_key_password);
            }
            g_config_context.config.client_key_password = strdup(value);
            break;
        #if OBS_ENABLE_GM_SUPPORT
        case OBS_CONFIG_GM_MODE_SWITCH:
            g_config_context.config.gm_mode_switch = atoi(value);
            break;
        #endif
        case OBS_CONFIG_SSL_MIN_VERSION: {
            long ssl_version;
            char temp_value[16] = {0};
            strncpy_s(temp_value, sizeof(temp_value), value, strlen(value));
            parse_ssl_version(temp_value, &ssl_version, CURL_SSLVERSION_TLSv1_2);
            g_config_context.config.ssl_min_version = ssl_version;
            break;
        }
        case OBS_CONFIG_SSL_MAX_VERSION: {
            long ssl_version;
            char temp_value[16] = {0};
            strncpy_s(temp_value, sizeof(temp_value), value, strlen(value));
            parse_ssl_version(temp_value, &ssl_version, (1 << 16) | 3);
            g_config_context.config.ssl_max_version = ssl_version;
            break;
        }
        case OBS_CONFIG_OCSP_STAPLING:
            g_config_context.config.ocsp_stapling = (strcmp(value, "true") == 0 || atoi(value) != 0);
            break;
        case OBS_CONFIG_CERTIFICATE_PIN:
            if (g_config_context.config.certificate_pin) {
                free(g_config_context.config.certificate_pin);
            }
            g_config_context.config.certificate_pin = strdup(value);
            break;
        case OBS_CONFIG_CERTIFICATE_PIN_COUNT:
            g_config_context.config.certificate_pin_count = atoi(value);
            break;
        case OBS_CONFIG_VERIFY_HOSTNAME:
            g_config_context.config.verify_hostname = (strcmp(value, "true") == 0 || atoi(value) != 0);
            break;
        case OBS_CONFIG_ENABLE_SESSION_TICKETS:
            g_config_context.config.enable_session_tickets = (strcmp(value, "true") == 0 || atoi(value) != 0);
            break;
        case OBS_CONFIG_SSL_SESSION_CACHE_TIMEOUT:
            g_config_context.config.ssl_session_cache_timeout = atoi(value);
            break;
        default:
            COMMLOG(OBS_LOGERROR, "Unsupported config item: %d", item);
            return -2;
    }

    // 更新配置来源
    g_config_context.source_map[item] = source;
    COMMLOG(OBS_LOGINFO, "Config item %s set from %s source: %s",
            config_item_names[item],
            (source == CONFIG_SOURCE_DEFAULT ? "default" :
             source == CONFIG_SOURCE_INI ? "ini file" :
             source == CONFIG_SOURCE_ENV ? "environment" : "API"),
            value);

    // 触发配置变更回调
    callback_node_t *current = g_callback_list;
    while (current) {
        current->callback(item, source);
        current = current->next;
    }

    return 0;
}

// 设置整数配置项值（内部函数）
static int config_set_int_internal(obs_config_item_t item, int value, config_source_t source)
{
    char str_value[64];
    sprintf_s(str_value, sizeof(str_value), "%d", value);
    return config_set_internal(item, str_value, source);
}

// 初始化默认配置
static void config_manager_init_default(void)
{
    memset(&g_config_context.config, 0, sizeof(obs_http_request_option));

    // 设置默认值
    g_config_context.config.speed_limit = 0;
    g_config_context.config.speed_time = 0;
    g_config_context.config.connect_time = 30;
    g_config_context.config.max_connected_time = 60;
    g_config_context.config.keep_alive = true;
    g_config_context.config.keep_idle = 60;
    g_config_context.config.keep_intvl = 60;
    g_config_context.config.proxy_host = NULL;
    g_config_context.config.proxy_auth = NULL;
    g_config_context.config.ssl_cipher_list = NULL;
    g_config_context.config.forbid_reuse_tcp = false;
    g_config_context.config.curl_max_connects = -1;
    g_config_context.config.http2_switch = OBS_HTTP2_CLOSE;
    g_config_context.config.bbr_switch = OBS_BBR_CLOSE;
    g_config_context.config.auth_switch = OBS_NEGOTIATION_TYPE;
    g_config_context.config.buffer_size = 0;
    g_config_context.config.server_cert_path = NULL;
    g_config_context.config.curl_log_verbose = false;
    g_config_context.config.mutual_ssl_switch = OBS_MUTUAL_SSL_CLOSE;
    g_config_context.config.client_cert_path = NULL;
    g_config_context.config.client_key_path = NULL;
    g_config_context.config.client_key_password = NULL;
    g_config_context.config.gm_mode_switch = OBS_GM_MODE_CLOSE;
    g_config_context.config.ssl_min_version = CURL_SSLVERSION_TLSv1_2;
    g_config_context.config.ssl_max_version = (1 << 16) | 3; // TLSv1.3

    // 高级SSL功能默认值
    g_config_context.config.ocsp_stapling = false;               // 禁用OCSP stapling
    g_config_context.config.certificate_pin = NULL;              // 未设置证书锁定
    g_config_context.config.certificate_pin_count = 0;           // 证书锁定哈希值数量为0
    g_config_context.config.verify_hostname = true;              // 启用主机名验证
    g_config_context.config.enable_session_tickets = true;       // 启用SSL会话票证
    g_config_context.config.ssl_session_cache_timeout = 300;     // SSL会话缓存超时时间为300秒

    // 标记所有配置项来源为默认值
    for (int i = 0; i < OBS_CONFIG_MAX_ITEMS; i++) {
        g_config_context.source_map[i] = CONFIG_SOURCE_DEFAULT;
    }

    COMMLOG(OBS_LOGDEBUG, "Default configuration initialized");
}

// 配置项名称到索引的映射
static int config_name_to_index(const char *name)
{
    for (int i = 0; i < OBS_CONFIG_MAX_ITEMS; i++) {
        if (strcmp(config_item_names[i], name) == 0) {
            return i;
        }
    }
    return -1;
}

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
static int parse_config_string_value(const char *line, char *buffer, size_t buffer_size)
{
    if (!line || !buffer || buffer_size == 0)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid parameters", __FUNCTION__);
        return -1;
    }

    char *value = strchr(line, '=');
    if (!value || !*(value + 1))
    {
        COMMLOG(OBS_LOGDEBUG, "%s No value found for config line: %s", __FUNCTION__, line);
        buffer[0] = '\0';
        return 0;
    }

    value++;
    size_t len = strlen(value);
    if (len > 0 && (value[len - 1] == '\n' || value[len - 1] == '\r'))
    {
        value[len - 1] = '\0';
        len--;
    }

    if (len == 0)
    {
        COMMLOG(OBS_LOGDEBUG, "%s Empty value for config line: %s", __FUNCTION__, line);
        buffer[0] = '\0';
        return 0;
    }

    if (len >= buffer_size)
    {
        COMMLOG(OBS_LOGERROR, "%s Config value length %zu exceeds buffer size %zu", __FUNCTION__, len, buffer_size);
        buffer[0] = '\0';
        return -2;
    }

    char temp_value[MAX_CONFIG_LINE] = {0};
    errno_t err = strncpy_s(temp_value, sizeof(temp_value), value, len);
    if (err != EOK)
    {
        COMMLOG(OBS_LOGERROR, "%s(%d): strncpy_s failed with error %d!", __FUNCTION__, __LINE__, err);
        buffer[0] = '\0';
        return -3;
    }

    char *trimmed_value = trim_string(temp_value);
    err = strcpy_s(buffer, buffer_size, trimmed_value, strlen(trimmed_value));
    if (err != EOK)
    {
        COMMLOG(OBS_LOGERROR, "%s(%d): strcpy_s failed with error %d!", __FUNCTION__, __LINE__, err);
        buffer[0] = '\0';
        return -4;
    }

    if (strlen(buffer) > 0)
    {
        COMMLOG(OBS_LOGDEBUG, "%s Parsed config value: %s", __FUNCTION__, buffer);
    }
    else
    {
        COMMLOG(OBS_LOGDEBUG, "%s Empty value after trimming for config line: %s", __FUNCTION__, line);
    }

    return 0;
}

// 辅助函数：分配并复制字符串
static int alloc_copy_string(const char *src, char **dest)
{
    if (!dest)
    {
        COMMLOG(OBS_LOGERROR, "%s Destination pointer is NULL", __FUNCTION__);
        return -1;
    }

    *dest = NULL;

    if (!src || src[0] == '\0')
    {
        COMMLOG(OBS_LOGDEBUG, "%s Source string is NULL or empty", __FUNCTION__);
        return 0;
    }

    size_t len = strlen(src);
    *dest = (char *)malloc(len + 1);
    if (!*dest)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to allocate memory for string: %s", __FUNCTION__, src);
        return -2;
    }

    errno_t err = strcpy_s(*dest, len + 1, src, len);
    if (err != EOK)
    {
        COMMLOG(OBS_LOGERROR, "%s(%d): strcpy_s failed with error %d!", __FUNCTION__, __LINE__, err);
        free(*dest);
        *dest = NULL;
        return -3;
    }

    COMMLOG(OBS_LOGINFO, "%s Allocated and copied string: %s", __FUNCTION__, src);
    return 0;
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

    int validation_result = 0;

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
        }
    }

    // 验证国密模式配置
    if (config->gm_mode_switch == OBS_GM_MODE_OPEN)
    {
        // 国密模式建议使用TLSv1.2
        if (config->ssl_min_version > CURL_SSLVERSION_TLSv1_2 || config->ssl_max_version < CURL_SSLVERSION_TLSv1_2)
        {
            COMMLOG(OBS_LOGWARN, "%s GM mode is enabled but SSL version range %ld to %ld is not compatible", __FUNCTION__, config->ssl_min_version, config->ssl_max_version);
            // 可以选择是否返回错误，这里作为警告处理
        }

        // 验证国密模式下的SSL密码套件配置
        if (config->ssl_cipher_list)
        {
            // 检查是否包含国密密码套件
            if (strstr(config->ssl_cipher_list, "SM") == NULL && strstr(config->ssl_cipher_list, "sm") == NULL)
            {
                COMMLOG(OBS_LOGWARN, "%s GM mode is enabled but cipher list does not contain SM algorithms: %s", __FUNCTION__, config->ssl_cipher_list);
                // 可以选择是否返回错误，这里作为警告处理
            }
        }
    }

    // 验证SSL版本范围配置
    if (config->ssl_min_version > config->ssl_max_version)
    {
        COMMLOG(OBS_LOGERROR, "%s SSL minimum version (%ld) is greater than maximum version (%ld)", __FUNCTION__, config->ssl_min_version, config->ssl_max_version);
        validation_result = -6;
    }

    // 验证服务器证书路径（如果提供）
    if (config->server_cert_path && strlen(config->server_cert_path) > 0)
    {
        if (access(config->server_cert_path, R_OK) != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Server certificate file not found or unreadable: %s", __FUNCTION__, config->server_cert_path);
            validation_result = -7;
        }
    }

    // 验证证书锁定配置
    if (config->certificate_pin)
    {
        if (strlen(config->certificate_pin) == 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Certificate pin is empty", __FUNCTION__);
            validation_result = -8;
        }
        else if (config->certificate_pin_count <= 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Certificate pin count must be greater than 0", __FUNCTION__);
            validation_result = -9;
        }
    }

    // 验证SSL会话缓存超时时间
    if (config->ssl_session_cache_timeout < 0)
    {
        COMMLOG(OBS_LOGERROR, "%s SSL session cache timeout must be a non-negative value", __FUNCTION__);
        validation_result = -10;
    }

    // 输出验证结果详细信息
    if (validation_result != 0)
    {
        COMMLOG(OBS_LOGDEBUG, "%s SSL configuration validation failed with error code: %d", __FUNCTION__, validation_result);
        // 可以添加更详细的错误信息，根据错误代码
    }
    else
    {
        COMMLOG(OBS_LOGDEBUG, "%s SSL configuration validation passed", __FUNCTION__);
    }

    return validation_result;
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
        int result = alloc_copy_string(client_cert_env, &options->request_options.client_cert_path);
        if (result != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Failed to copy client certificate path from environment variable, error code: %d", __FUNCTION__, result);
        }
    }

    const char *client_key_env = getenv("OBS_CLIENT_KEY_PATH");
    if (client_key_env)
    {
        int result = alloc_copy_string(client_key_env, &options->request_options.client_key_path);
        if (result != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Failed to copy client key path from environment variable, error code: %d", __FUNCTION__, result);
        }
    }

    const char *client_key_pass_env = getenv("OBS_CLIENT_KEY_PASSWORD");
    if (client_key_pass_env)
    {
        int result = alloc_copy_string(client_key_pass_env, &options->request_options.client_key_password);
        if (result != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Failed to copy client key password from environment variable, error code: %d", __FUNCTION__, result);
        }
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
        int result = alloc_copy_string(ssl_cipher_env, &options->request_options.ssl_cipher_list);
        if (result != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Failed to copy SSL cipher list from environment variable, error code: %d", __FUNCTION__, result);
        }
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

    // 高级SSL功能配置
    const char *ocsp_stapling_env = getenv("OBS_OCSP_STAPLING");
    if (ocsp_stapling_env)
    {
        if (strcmp(ocsp_stapling_env, "true") == 0 || strcmp(ocsp_stapling_env, "1") == 0)
        {
            options->request_options.ocsp_stapling = true;
            COMMLOG(OBS_LOGINFO, "%s OCSP stapling enabled from environment variable", __FUNCTION__);
        }
        else if (strcmp(ocsp_stapling_env, "false") == 0 || strcmp(ocsp_stapling_env, "0") == 0)
        {
            options->request_options.ocsp_stapling = false;
            COMMLOG(OBS_LOGINFO, "%s OCSP stapling disabled from environment variable", __FUNCTION__);
        }
    }

    const char *certificate_pin_env = getenv("OBS_CERTIFICATE_PIN");
    if (certificate_pin_env)
    {
        int result = alloc_copy_string(certificate_pin_env, &options->request_options.certificate_pin);
        if (result != 0)
        {
            COMMLOG(OBS_LOGERROR, "%s Failed to copy certificate pin from environment variable, error code: %d", __FUNCTION__, result);
        }
    }

    const char *certificate_pin_count_env = getenv("OBS_CERTIFICATE_PIN_COUNT");
    if (certificate_pin_count_env)
    {
        options->request_options.certificate_pin_count = atoi(certificate_pin_count_env);
        COMMLOG(OBS_LOGINFO, "%s Certificate pin count set from environment variable: %d", __FUNCTION__, options->request_options.certificate_pin_count);
    }

    const char *verify_hostname_env = getenv("OBS_VERIFY_HOSTNAME");
    if (verify_hostname_env)
    {
        if (strcmp(verify_hostname_env, "true") == 0 || strcmp(verify_hostname_env, "1") == 0)
        {
            options->request_options.verify_hostname = true;
            COMMLOG(OBS_LOGINFO, "%s Hostname verification enabled from environment variable", __FUNCTION__);
        }
        else if (strcmp(verify_hostname_env, "false") == 0 || strcmp(verify_hostname_env, "0") == 0)
        {
            options->request_options.verify_hostname = false;
            COMMLOG(OBS_LOGINFO, "%s Hostname verification disabled from environment variable", __FUNCTION__);
        }
    }

    const char *enable_session_tickets_env = getenv("OBS_ENABLE_SESSION_TICKETS");
    if (enable_session_tickets_env)
    {
        if (strcmp(enable_session_tickets_env, "true") == 0 || strcmp(enable_session_tickets_env, "1") == 0)
        {
            options->request_options.enable_session_tickets = true;
            COMMLOG(OBS_LOGINFO, "%s SSL session tickets enabled from environment variable", __FUNCTION__);
        }
        else if (strcmp(enable_session_tickets_env, "false") == 0 || strcmp(enable_session_tickets_env, "0") == 0)
        {
            options->request_options.enable_session_tickets = false;
            COMMLOG(OBS_LOGINFO, "%s SSL session tickets disabled from environment variable", __FUNCTION__);
        }
    }

    const char *ssl_session_cache_timeout_env = getenv("OBS_SSL_SESSION_CACHE_TIMEOUT");
    if (ssl_session_cache_timeout_env)
    {
        options->request_options.ssl_session_cache_timeout = atoi(ssl_session_cache_timeout_env);
        COMMLOG(OBS_LOGINFO, "%s SSL session cache timeout set from environment variable: %d seconds", __FUNCTION__, options->request_options.ssl_session_cache_timeout);
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

    // 高级SSL功能默认值
    options->ocsp_stapling = false;               // 禁用OCSP stapling
    options->certificate_pin = NULL;              // 未设置证书锁定
    options->certificate_pin_count = 0;           // 证书锁定哈希值数量为0
    options->verify_hostname = true;              // 启用主机名验证
    options->enable_session_tickets = true;       // 启用SSL会话票证
    options->ssl_session_cache_timeout = 300;     // SSL会话缓存超时时间为300秒

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

// 验证配置文件内容格式的有效性
static int validate_config_file_format(FILE *fp)
{
    if (!fp)
    {
        COMMLOG(OBS_LOGERROR, "%s Invalid file pointer", __FUNCTION__);
        return -1;
    }

    int has_ssl_config_section = 0;
    char line[MAX_CONFIG_LINE] = {0};
    int line_number = 0;

    // 重置文件指针到开头
    if (fseek(fp, 0L, SEEK_SET) != 0)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to rewind config file", __FUNCTION__);
        return -2;
    }

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
            has_ssl_config_section = 1;
            COMMLOG(OBS_LOGDEBUG, "%s Found SSLConfig section at line %d", __FUNCTION__, line_number);
            continue;
        }

        // 在SSL配置段内，验证配置项格式
        if (has_ssl_config_section)
        {
            // 检查是否开始了新的配置段
            if (line[0] == '[')
            {
                break;
            }

            // 验证配置项格式是否正确（key=value）
            if (strchr(line, '=') == NULL)
            {
                COMMLOG(OBS_LOGWARN, "%s Invalid config line format at line %d: %s", __FUNCTION__, line_number, line);
                continue;  // 继续处理其他配置项，而不是停止解析
            }

            // 简单验证配置项名称是否符合预期
            char *key = strtok(line, "=");
            if (key)
            {
                char *trimmed_key = trim_string(key);

                // 检查配置项名称是否有效（包含禁止的字符）
                if (strpbrk(trimmed_key, "[]{}()!@#$%^&*`~") != NULL)
                {
                    COMMLOG(OBS_LOGWARN, "%s Invalid config key name at line %d: %s", __FUNCTION__, line_number, trimmed_key);
                }
            }
        }
    }

    // 重置文件指针到开头，以便后续读取
    if (fseek(fp, 0L, SEEK_SET) != 0)
    {
        COMMLOG(OBS_LOGERROR, "%s Failed to rewind config file", __FUNCTION__);
        return -3;
    }

    if (!has_ssl_config_section)
    {
        COMMLOG(OBS_LOGWARN, "%s SSLConfig section not found in config file", __FUNCTION__);
        return 0;  // 配置文件可能是有效的，但没有SSL配置段
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

/**
 * @brief 初始化配置管理系统
 */
void config_manager_init(void)
{
    if (g_config_context.is_initialized) {
        COMMLOG(OBS_LOGWARN, "Config manager already initialized");
        return;
    }

    config_manager_init_default();
    g_config_context.is_initialized = 1;

    COMMLOG(OBS_LOGINFO, "Config manager initialized");
}

/**
 * @brief 销毁配置管理系统
 */
void config_manager_destroy(void)
{
    if (!g_config_context.is_initialized) {
        COMMLOG(OBS_LOGWARN, "Config manager not initialized");
        return;
    }

    // 释放字符串资源
    if (g_config_context.config.proxy_host) {
        free(g_config_context.config.proxy_host);
    }
    if (g_config_context.config.proxy_auth) {
        free(g_config_context.config.proxy_auth);
    }
    if (g_config_context.config.ssl_cipher_list) {
        free(g_config_context.config.ssl_cipher_list);
    }
    if (g_config_context.config.server_cert_path) {
        free(g_config_context.config.server_cert_path);
    }
    if (g_config_context.config.client_cert_path) {
        free(g_config_context.config.client_cert_path);
    }
    if (g_config_context.config.client_key_path) {
        free(g_config_context.config.client_key_path);
    }
    if (g_config_context.config.client_key_password) {
        free(g_config_context.config.client_key_password);
    }
    if (g_config_context.config.certificate_pin) {
        free(g_config_context.config.certificate_pin);
    }

    // 清除回调列表
    callback_node_t *current = g_callback_list;
    while (current) {
        callback_node_t *next = current->next;
        free(current);
        current = next;
    }
    g_callback_list = NULL;

    // 重置配置上下文
    memset(&g_config_context, 0, sizeof(config_context_t));

    COMMLOG(OBS_LOGINFO, "Config manager destroyed");
}

/**
 * @brief 从配置文件加载配置
 */
static int config_manager_load_ini(void)
{
    char *config_path = get_config_file_path();
    if (!config_path) {
        COMMLOG(OBS_LOGWARN, "Config file not found in any standard locations");
        return -1;
    }

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        COMMLOG(OBS_LOGERROR, "Failed to open config file: %s", config_path);
        free(config_path);
        return -2;
    }

    int format_validity = validate_config_file_format(fp);
    if (format_validity < 0) {
        COMMLOG(OBS_LOGERROR, "Failed to validate config file format, error code: %d", format_validity);
        fclose(fp);
        free(config_path);
        return -3;
    }

    COMMLOG(OBS_LOGINFO, "Loading SSL configuration from: %s", config_path);

    char line[MAX_CONFIG_LINE] = {0};
    int in_ssl_config = 0;

    int line_number = 0;
    while (fgets(line, sizeof(line), fp)) {
        line_number++;
        if (line[0] == '\n' || line[0] == '#' || line[0] == ';' || line[0] == '\r') {
            continue;
        }

        if (strstr(line, "[SSLConfig]")) {
            in_ssl_config = 1;
            COMMLOG(OBS_LOGDEBUG, "Found SSLConfig section at line %d", line_number);
            continue;
        } else if (line[0] == '[') {
            in_ssl_config = 0;
            continue;
        }

        if (!in_ssl_config) {
            continue;
        }

        char key[MAX_CONFIG_LINE] = {0};
        char value[MAX_CONFIG_LINE] = {0};
        char *eq_pos = strchr(line, '=');
        if (eq_pos) {
            int key_len = eq_pos - line;
            strncpy_s(key, sizeof(key), line, key_len);
            key[key_len] = '\0';

            trim_string(key);
            trim_string(eq_pos + 1);
            strncpy_s(value, sizeof(value), eq_pos + 1, strlen(eq_pos + 1));
            value[strcspn(value, "\r\n")] = '\0';

            // 将配置项名称转换为枚举值
            int item_index = -1;
            if (strcmp(key, "MutualSSLEnabled") == 0) {
                item_index = OBS_CONFIG_MUTUAL_SSL_SWITCH;
                if (strcmp(value, "true") == 0) {
                    strcpy_s(value, sizeof(value), "1"); // OBS_MUTUAL_SSL_OPEN
                } else if (strcmp(value, "false") == 0) {
                    strcpy_s(value, sizeof(value), "0"); // OBS_MUTUAL_SSL_CLOSE
                }
            } else if (strcmp(key, "ClientCertPath") == 0) {
                item_index = OBS_CONFIG_CLIENT_CERT_PATH;
            } else if (strcmp(key, "ClientKeyPath") == 0) {
                item_index = OBS_CONFIG_CLIENT_KEY_PATH;
            } else if (strcmp(key, "ClientKeyPassword") == 0) {
                item_index = OBS_CONFIG_CLIENT_KEY_PASSWORD;
            } else if (strcmp(key, "GMModeEnabled") == 0) {
                item_index = OBS_CONFIG_GM_MODE_SWITCH;
                if (strcmp(value, "true") == 0) {
                    strcpy_s(value, sizeof(value), "1"); // OBS_GM_MODE_OPEN
                } else if (strcmp(value, "false") == 0) {
                    strcpy_s(value, sizeof(value), "0"); // OBS_GM_MODE_CLOSE
                }
            } else if (strcmp(key, "CipherList") == 0) {
                item_index = OBS_CONFIG_SSL_CIPHER_LIST;
            } else if (strcmp(key, "SSLMinVersion") == 0) {
                item_index = OBS_CONFIG_SSL_MIN_VERSION;
            } else if (strcmp(key, "SSLMaxVersion") == 0) {
                item_index = OBS_CONFIG_SSL_MAX_VERSION;
            } else if (strcmp(key, "OCSPStapling") == 0) {
                item_index = OBS_CONFIG_OCSP_STAPLING;
                if (strcmp(value, "true") == 0) {
                    strcpy_s(value, sizeof(value), "1");
                } else if (strcmp(value, "false") == 0) {
                    strcpy_s(value, sizeof(value), "0");
                }
            } else if (strcmp(key, "CertificatePin") == 0) {
                item_index = OBS_CONFIG_CERTIFICATE_PIN;
            } else if (strcmp(key, "CertificatePinCount") == 0) {
                item_index = OBS_CONFIG_CERTIFICATE_PIN_COUNT;
            } else if (strcmp(key, "VerifyHostname") == 0) {
                item_index = OBS_CONFIG_VERIFY_HOSTNAME;
                if (strcmp(value, "true") == 0) {
                    strcpy_s(value, sizeof(value), "1");
                } else if (strcmp(value, "false") == 0) {
                    strcpy_s(value, sizeof(value), "0");
                }
            } else if (strcmp(key, "EnableSessionTickets") == 0) {
                item_index = OBS_CONFIG_ENABLE_SESSION_TICKETS;
                if (strcmp(value, "true") == 0) {
                    strcpy_s(value, sizeof(value), "1");
                } else if (strcmp(value, "false") == 0) {
                    strcpy_s(value, sizeof(value), "0");
                }
            } else if (strcmp(key, "SSLSessionCacheTimeout") == 0) {
                item_index = OBS_CONFIG_SSL_SESSION_CACHE_TIMEOUT;
            }

            if (item_index != -1) {
                config_set_internal(item_index, value, CONFIG_SOURCE_INI);
            } else {
                COMMLOG(OBS_LOGWARN, "Unknown config key: %s", key);
            }
        }
    }

    fclose(fp);
    free(config_path);

    return 0;
}

/**
 * @brief 从环境变量加载配置
 */
static int config_manager_load_env(void)
{
    const char *env_vars[] = {
        "OBS_MUTUAL_SSL_ENABLED",
        "OBS_CLIENT_CERT_PATH",
        "OBS_CLIENT_KEY_PATH",
        "OBS_CLIENT_KEY_PASSWORD",
        "OBS_GM_MODE_ENABLED",
        "OBS_SSL_CIPHER_LIST",
        "OBS_SSL_MIN_VERSION",
        "OBS_SSL_MAX_VERSION",
        "OBS_OCSP_STAPLING",
        "OBS_CERTIFICATE_PIN",
        "OBS_CERTIFICATE_PIN_COUNT",
        "OBS_VERIFY_HOSTNAME",
        "OBS_ENABLE_SESSION_TICKETS",
        "OBS_SSL_SESSION_CACHE_TIMEOUT"
    };

    obs_config_item_t config_items[] = {
        OBS_CONFIG_MUTUAL_SSL_SWITCH,
        OBS_CONFIG_CLIENT_CERT_PATH,
        OBS_CONFIG_CLIENT_KEY_PATH,
        OBS_CONFIG_CLIENT_KEY_PASSWORD,
        OBS_CONFIG_GM_MODE_SWITCH,
        OBS_CONFIG_SSL_CIPHER_LIST,
        OBS_CONFIG_SSL_MIN_VERSION,
        OBS_CONFIG_SSL_MAX_VERSION,
        OBS_CONFIG_OCSP_STAPLING,
        OBS_CONFIG_CERTIFICATE_PIN,
        OBS_CONFIG_CERTIFICATE_PIN_COUNT,
        OBS_CONFIG_VERIFY_HOSTNAME,
        OBS_CONFIG_ENABLE_SESSION_TICKETS,
        OBS_CONFIG_SSL_SESSION_CACHE_TIMEOUT
    };

    for (int i = 0; i < sizeof(env_vars) / sizeof(env_vars[0]); i++) {
        const char *env_value = getenv(env_vars[i]);
        if (env_value) {
            char value[MAX_CONFIG_LINE] = {0};
            strncpy_s(value, sizeof(value), env_value, strlen(env_value));

            // 处理布尔类型的配置
            if (i == 0 || i == 4) { // MutualSSLEnabled 或 GMModeEnabled
                if (strcmp(env_value, "true") == 0 || strcmp(env_value, "1") == 0) {
                    strcpy_s(value, sizeof(value), "1"); // Open
                } else if (strcmp(env_value, "false") == 0 || strcmp(env_value, "0") == 0) {
                    strcpy_s(value, sizeof(value), "0"); // Close
                }
            }

            config_set_internal(config_items[i], value, CONFIG_SOURCE_ENV);
        }
    }

    return 0;
}

/**
 * @brief 加载完整配置
 */
int config_manager_load(void)
{
    if (!g_config_context.is_initialized) {
        COMMLOG(OBS_LOGERROR, "Config manager not initialized");
        return -1;
    }

    int ini_result = config_manager_load_ini();
    int env_result = config_manager_load_env();

    // 验证配置
    int validation_result = validate_ssl_config(&g_config_context.config);
    if (validation_result != 0) {
        COMMLOG(OBS_LOGERROR, "SSL configuration validation failed with error code: %d", validation_result);
        return -3;
    }

    COMMLOG(OBS_LOGINFO, "Configuration loaded successfully");

    if (ini_result != 0) {
        COMMLOG(OBS_LOGWARN, "Failed to load config from ini file, but environment variables may have been loaded");
    }

    return 0;
}

/**
 * @brief 获取配置
 */
void config_manager_get(obs_http_request_option *config)
{
    if (!g_config_context.is_initialized) {
        COMMLOG(OBS_LOGERROR, "Config manager not initialized");
        init_http_request_option(config);
        return;
    }

    if (config) {
        memcpy(config, &g_config_context.config, sizeof(obs_http_request_option));
    }
}

/**
 * @brief 设置配置项
 */
int config_manager_set(obs_config_item_t item, const char *value)
{
    if (!g_config_context.is_initialized) {
        COMMLOG(OBS_LOGERROR, "Config manager not initialized");
        return -1;
    }

    if (!value) {
        COMMLOG(OBS_LOGERROR, "Value parameter is NULL");
        return -2;
    }

    return config_set_internal(item, value, CONFIG_SOURCE_API);
}

/**
 * @brief 设置整数配置项
 */
int config_manager_set_int(obs_config_item_t item, int value)
{
    if (!g_config_context.is_initialized) {
        COMMLOG(OBS_LOGERROR, "Config manager not initialized");
        return -1;
    }

    return config_set_int_internal(item, value, CONFIG_SOURCE_API);
}

/**
 * @brief 获取配置项的来源
 */
config_source_t config_manager_get_source(obs_config_item_t item)
{
    if (!g_config_context.is_initialized) {
        COMMLOG(OBS_LOGERROR, "Config manager not initialized");
        return CONFIG_SOURCE_DEFAULT;
    }

    if (item < 0 || item >= OBS_CONFIG_MAX_ITEMS) {
        COMMLOG(OBS_LOGERROR, "Invalid config item: %d", item);
        return CONFIG_SOURCE_DEFAULT;
    }

    return g_config_context.source_map[item];
}

/**
 * @brief 注册配置变更监听回调
 */
void config_manager_register_callback(config_change_callback_t callback)
{
    if (!callback) {
        COMMLOG(OBS_LOGERROR, "Callback parameter is NULL");
        return;
    }

    // 检查回调是否已注册
    callback_node_t *current = g_callback_list;
    while (current) {
        if (current->callback == callback) {
            COMMLOG(OBS_LOGWARN, "Callback already registered");
            return;
        }
        current = current->next;
    }

    // 创建新的回调节点
    callback_node_t *new_node = (callback_node_t *)malloc(sizeof(callback_node_t));
    if (!new_node) {
        COMMLOG(OBS_LOGERROR, "Failed to allocate memory for callback node");
        return;
    }

    new_node->callback = callback;
    new_node->next = g_callback_list;
    g_callback_list = new_node;

    COMMLOG(OBS_LOGINFO, "Config change callback registered");
}

/**
 * @brief 卸载配置变更监听回调
 */
void config_manager_unregister_callback(config_change_callback_t callback)
{
    if (!callback) {
        COMMLOG(OBS_LOGERROR, "Callback parameter is NULL");
        return;
    }

    callback_node_t **current = &g_callback_list;
    while (*current) {
        if ((*current)->callback == callback) {
            callback_node_t *temp = *current;
            *current = temp->next;
            free(temp);
            COMMLOG(OBS_LOGINFO, "Config change callback unregistered");
            return;
        }
        current = &((*current)->next);
    }

    COMMLOG(OBS_LOGWARN, "Callback not found");
}

/**
 * @brief 导出配置到字符串
 */
int config_manager_export(char *buffer, int buffer_size)
{
    if (!g_config_context.is_initialized) {
        COMMLOG(OBS_LOGERROR, "Config manager not initialized");
        return -1;
    }

    if (!buffer || buffer_size <= 0) {
        COMMLOG(OBS_LOGERROR, "Invalid parameters");
        return -2;
    }

    int offset = 0;
    int result = 0;

    result = sprintf_s(buffer + offset, buffer_size - offset, "SSL Configuration:\n");
    if (result < 0) return -3;
    offset += result;

    // 导出每个配置项
    for (int i = 0; i < OBS_CONFIG_MAX_ITEMS; i++) {
        const char *source_str;
        switch (g_config_context.source_map[i]) {
            case CONFIG_SOURCE_DEFAULT:
                source_str = "Default";
                break;
            case CONFIG_SOURCE_INI:
                source_str = "INI File";
                break;
            case CONFIG_SOURCE_ENV:
                source_str = "Environment";
                break;
            case CONFIG_SOURCE_API:
                source_str = "API";
                break;
            default:
                source_str = "Unknown";
        }

        char value_str[128] = {0};
        switch (i) {
            case OBS_CONFIG_SPEED_LIMIT:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.speed_limit);
                break;
            case OBS_CONFIG_SPEED_TIME:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.speed_time);
                break;
            case OBS_CONFIG_CONNECT_TIME:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.connect_time);
                break;
            case OBS_CONFIG_MAX_CONNECTED_TIME:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.max_connected_time);
                break;
            case OBS_CONFIG_KEEP_ALIVE:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.keep_alive ? "true" : "false");
                break;
            case OBS_CONFIG_KEEP_IDLE:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.keep_idle);
                break;
            case OBS_CONFIG_KEEP_INTVL:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.keep_intvl);
                break;
            case OBS_CONFIG_PROXY_HOST:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.proxy_host ? g_config_context.config.proxy_host : "NULL");
                break;
            case OBS_CONFIG_PROXY_AUTH:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.proxy_auth ? g_config_context.config.proxy_auth : "NULL");
                break;
            case OBS_CONFIG_SSL_CIPHER_LIST:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.ssl_cipher_list ? g_config_context.config.ssl_cipher_list : "NULL");
                break;
            case OBS_CONFIG_FORBID_REUSE_TCP:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.forbid_reuse_tcp ? "true" : "false");
                break;
            case OBS_CONFIG_CURL_MAX_CONNECTS:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.curl_max_connects);
                break;
            case OBS_CONFIG_HTTP2_SWITCH:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.http2_switch);
                break;
            case OBS_CONFIG_BBR_SWITCH:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.bbr_switch);
                break;
            case OBS_CONFIG_AUTH_SWITCH:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.auth_switch);
                break;
            case OBS_CONFIG_BUFFER_SIZE:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.buffer_size);
                break;
            case OBS_CONFIG_SERVER_CERT_PATH:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.server_cert_path ? g_config_context.config.server_cert_path : "NULL");
                break;
            case OBS_CONFIG_CURL_LOG_VERBOSE:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.curl_log_verbose ? "true" : "false");
                break;
            case OBS_CONFIG_MUTUAL_SSL_SWITCH:
                sprintf_s(value_str, sizeof(value_str), "%s", (g_config_context.config.mutual_ssl_switch == OBS_MUTUAL_SSL_OPEN) ? "OPEN" : "CLOSE");
                break;
            case OBS_CONFIG_CLIENT_CERT_PATH:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.client_cert_path ? g_config_context.config.client_cert_path : "NULL");
                break;
            case OBS_CONFIG_CLIENT_KEY_PATH:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.client_key_path ? g_config_context.config.client_key_path : "NULL");
                break;
            case OBS_CONFIG_CLIENT_KEY_PASSWORD:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.client_key_password ? g_config_context.config.client_key_password : "NULL");
                break;
            case OBS_CONFIG_GM_MODE_SWITCH:
                sprintf_s(value_str, sizeof(value_str), "%s", (g_config_context.config.gm_mode_switch == OBS_GM_MODE_OPEN) ? "OPEN" : "CLOSE");
                break;
            case OBS_CONFIG_SSL_MIN_VERSION:
                sprintf_s(value_str, sizeof(value_str), "0x%08lX", (long)g_config_context.config.ssl_min_version);
                break;
            case OBS_CONFIG_SSL_MAX_VERSION:
                sprintf_s(value_str, sizeof(value_str), "0x%08lX", (long)g_config_context.config.ssl_max_version);
                break;
            case OBS_CONFIG_OCSP_STAPLING:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.ocsp_stapling ? "true" : "false");
                break;
            case OBS_CONFIG_CERTIFICATE_PIN:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.certificate_pin ? g_config_context.config.certificate_pin : "NULL");
                break;
            case OBS_CONFIG_CERTIFICATE_PIN_COUNT:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.certificate_pin_count);
                break;
            case OBS_CONFIG_VERIFY_HOSTNAME:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.verify_hostname ? "true" : "false");
                break;
            case OBS_CONFIG_ENABLE_SESSION_TICKETS:
                sprintf_s(value_str, sizeof(value_str), "%s", g_config_context.config.enable_session_tickets ? "true" : "false");
                break;
            case OBS_CONFIG_SSL_SESSION_CACHE_TIMEOUT:
                sprintf_s(value_str, sizeof(value_str), "%d", g_config_context.config.ssl_session_cache_timeout);
                break;
            default:
                sprintf_s(value_str, sizeof(value_str), "Unknown");
        }

        result = sprintf_s(buffer + offset, buffer_size - offset, "  %-30s: %-20s (%s)\n",
                          config_item_names[i], value_str, source_str);
        if (result < 0) return -3;
        offset += result;
    }

    // 添加验证结果
    int validation_result = validate_ssl_config(&g_config_context.config);
    result = sprintf_s(buffer + offset, buffer_size - offset, "\nConfiguration Validation: %s\n",
                      validation_result == 0 ? "PASSED" : "FAILED");
    if (result < 0) return -3;

    return 0;
}

// 保持与旧接口的兼容性
void load_ssl_config_from_ini(obs_options *options)
{
    if (!g_config_context.is_initialized) {
        config_manager_init();
    }

    int result = config_manager_load_ini();
    if (result != 0) {
        COMMLOG(OBS_LOGWARN, "Failed to load config from ini file");
    }

    // 将配置复制到 options 结构体
    memcpy(&options->request_options, &g_config_context.config, sizeof(obs_http_request_option));

    // 加载环境变量配置（保持旧接口的行为）
    load_ssl_config_from_env(options);

    // 验证配置
    int validation_result = validate_ssl_config(&options->request_options);
    if (validation_result != 0) {
        COMMLOG(OBS_LOGERROR, "SSL configuration validation failed with error code: %d", validation_result);
    } else {
        COMMLOG(OBS_LOGDEBUG, "SSL configuration validation passed");
    }
}
