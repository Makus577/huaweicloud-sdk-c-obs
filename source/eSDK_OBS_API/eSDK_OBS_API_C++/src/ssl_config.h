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
#ifndef SSL_CONFIG_H
#define SSL_CONFIG_H

#include "eSDKOBS.h"

// 初始化HTTP请求配置选项
void init_http_request_option(obs_http_request_option *options);

// 从配置文件加载 SSL 配置
void load_ssl_config_from_ini(obs_options *options);

#endif /* SSL_CONFIG_H */
