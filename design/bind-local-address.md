# Minimax 执行说明：OBS C SDK 增加本地源端口/网卡绑定能力

## 摘要
目标是在 OBS C SDK 的公共请求参数中新增两类能力，并确保所有请求链路行为一致、默认行为不变、出错可定位：

- 支持通过参数绑定请求的本地源端口，或从指定起始端口开始的端口范围
- 支持通过参数绑定本地出接口，输入允许“网卡名”或“本地 IP”，直接透传 libcurl

本次实现只开放 API 参数入口，不接配置文件、不接环境变量、不做平台特化扩展。底层直接使用 libcurl：
- `CURLOPT_INTERFACE`
- `CURLOPT_LOCALPORT`
- `CURLOPT_LOCALPORTRANGE`

## 设计定稿
### 对外字段
在 [eSDKOBS.h](/Users/wuchengqi/huaweicloud/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++/inc/eSDKOBS.h) 的 `obs_http_request_option` 中新增以下字段，放在现有网络请求参数区域，命名固定，不再变更：

- `char *outgoing_interface;`
- `long local_port;`
- `long local_port_range;`

### 字段语义
语义按 libcurl 原生语义固定如下：

- `outgoing_interface == NULL`
  表示不绑定本地网卡/本地地址
- `outgoing_interface != NULL`
  透传给 `CURLOPT_INTERFACE`，允许传网卡名或本地 IP
- `local_port == 0`
  表示不绑定本地源端口
- `local_port > 0 && local_port_range == 1`
  表示仅绑定单端口
- `local_port > 0 && local_port_range > 1`
  表示从 `local_port` 开始，总共尝试 `local_port_range` 个端口

### 默认值
在 [general.c](/Users/wuchengqi/huaweicloud/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++/src/general.c) 的 `init_obs_options()` 中新增默认初始化：

- `outgoing_interface = NULL`
- `local_port = 0`
- `local_port_range = 1`

这组默认值视为“未启用新能力”，要求与当前版本默认行为完全一致。

### 参数校验规则
新增统一校验函数，常规请求和 API 协商请求都必须共用，规则固定如下：

- `outgoing_interface == NULL`：合法
- `outgoing_interface != NULL && outgoing_interface[0] == '\0'`：非法，返回 `OBS_STATUS_InvalidParameter`
- `local_port` 只允许 `0` 或 `1..65535`
- `local_port == 0` 时，`local_port_range` 必须为 `1`
- `local_port > 0` 时，`local_port_range` 必须为 `1..65535`
- `local_port + local_port_range - 1` 不得大于 `65535`

校验必须在实际发起网络请求前完成，非法配置直接返回 `OBS_STATUS_InvalidParameter`，不得进入 `curl_easy_perform()`。

### 错误映射规则
在 [request_util.c](/Users/wuchengqi/huaweicloud/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++/src/request_util.c) 的 `request_curl_code_to_status()` 中补充：

- `CURLE_INTERFACE_FAILED -> OBS_STATUS_FailedToConnect`

这样可以覆盖网卡名错误、本地地址不可绑定等场景，避免返回模糊的 `InternalError`。

不新增新的 `obs_status` 枚举值，避免扩大接口面和联动成本。

## 实施步骤
### 1. 扩展公共结构体和默认初始化
修改 [eSDKOBS.h](/Users/wuchengqi/huaweicloud/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++/inc/eSDKOBS.h)：

- 在 `obs_http_request_option` 中新增 3 个字段
- 给新增字段补简短注释，明确“本地源端口/本地出接口”含义，避免被误解成 OBS 服务端口

修改 [general.c](/Users/wuchengqi/huaweicloud/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++/src/general.c)：

- 在 `init_obs_options()` 里补默认值初始化
- 不修改任何旧字段默认值

### 2. 增加统一校验函数
在 [request.c](/Users/wuchengqi/huaweicloud/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++/src/request.c) 或其配套头文件中新增一个静态校验函数，建议命名为：

- `static obs_status validate_bind_request_options(const obs_http_request_option *request_options)`

实现要求：

- 只做本次新增字段的校验
- 不混入其他老参数逻辑
- 返回值只用 `OBS_STATUS_OK` 或 `OBS_STATUS_InvalidParameter`
- 打日志时把非法字段值打印出来，便于排障

调用点固定为两处：
- 常规请求链路，在 `setup_curl()` 进入具体 `curl_easy_setopt` 之前调用
- 协商探测链路，在 `get_api_version()` 进入具体 `curl_easy_setopt` 之前调用

### 3. 抽取统一的 curl 绑定设置逻辑
为避免两条链路重复和后续跑偏，在 [request.c](/Users/wuchengqi/huaweicloud/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++/src/request.c) 抽一个小函数，建议命名为：

- `static obs_status apply_bind_request_options(CURL *curl, const obs_http_request_option *request_options)`

函数行为固定为：

- 若 `outgoing_interface != NULL`，调用 `CURLOPT_INTERFACE`
- 若 `local_port > 0`，调用 `CURLOPT_LOCALPORT`
- 若 `local_port > 0`，调用 `CURLOPT_LOCALPORTRANGE`
- 若任一 `curl_easy_setopt` 失败，返回 `OBS_STATUS_FailedToIInitializeRequest`

注意事项固定如下：

- 不设置 `CURLOPT_DNS_INTERFACE`
- 不设置 `CURLOPT_DNS_LOCAL_IP4`
- 不设置 `CURLOPT_DNS_LOCAL_IP6`
- 不做字符串复制，沿用当前 SDK 对 `request_options` 中字符串字段的使用方式
- `local_port == 0` 时，不调用端口相关 curl option

### 4. 接入两条请求链路
修改 [request.c](/Users/wuchengqi/huaweicloud/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++/src/request.c) 的两个入口：

#### 常规请求链路
在 `setup_curl()` 中：
- 先校验 `request_option`
- 再应用 bind 相关 curl option
- 再继续设置其他已有 curl option

#### 协商探测链路
在 `get_api_version()` 中：
- 同样先校验 `request_options`
- 同样应用 bind 相关 curl option

要求两条链路行为完全一致，否则会出现：
- 协商阶段没绑定
- 正式请求已绑定
或反过来
这类隐蔽问题

### 5. 补日志
在新增校验失败和 curl 执行失败场景中，日志至少包含：

- `outgoing_interface`
- `local_port`
- `local_port_range`
- `curl code`
- `curl error buffer`

日志目的不是增加大量输出，而是保证定位这类网络源绑定问题时有最小必要信息。

### 6. 更新 Demo / 说明
优先更新 Demo 示例，而不是只改 readme 文本。修改范围建议放在：
- [demo_common.c](/Users/wuchengqi/huaweicloud/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++_Demo/demo_common.c)
- 或 Demo 初始化 `obs_options` 的示例位置

至少给出 3 种示例代码片段：

- 绑定本地 IP 或网卡
- 绑定单端口
- 同时绑定本地网卡和端口范围

说明文字必须明确写清：
- 这是“本地源地址/源端口”绑定
- 不是目标服务端口
- `local_port_range` 是“尝试数量”，不是结束端口

## 验收口径
### A. 兼容性验收
以下场景必须与当前版本行为一致：

- 用户不设置任何新字段
- 用户仅调用 `init_obs_options()` 后直接发请求
- 默认协商鉴权链路 `get_api_version()` 正常工作
- 现有代理、超时、keepalive、证书等能力不受影响

验收标准：
- 编译通过
- 现有主要请求路径可正常运行
- 默认情况下没有新增错误码、没有新增异常日志、没有行为回归

### B. 参数校验验收
以下输入必须直接返回 `OBS_STATUS_InvalidParameter`，且不进入 `curl_easy_perform()`：

- `outgoing_interface = ""`
- `local_port < 0`
- `local_port > 65535`
- `local_port == 0 && local_port_range != 1`
- `local_port > 0 && local_port_range <= 0`
- `local_port > 0 && local_port + local_port_range - 1 > 65535`

### C. 正常功能验收
以下配置必须能正确下发到 libcurl：

- `outgoing_interface = "eth0"` 或 `"en0"` 或某个本地 IP
- `local_port = 30000, local_port_range = 1`
- `local_port = 30000, local_port_range = 20`
- `outgoing_interface + local_port + local_port_range` 同时配置

验收标准：
- 常规请求链路生效
- `get_api_version()` 链路也生效
- 没有只在某一条链路生效的分叉

### D. 失败场景验收
以下场景必须可识别、可定位：

- 网卡名不存在或本地地址不可用时，返回 `OBS_STATUS_FailedToConnect`
- 端口被占满、范围内无可用端口时，返回连接失败类错误，不得静默退化为系统随机端口
- 错误日志里能看到 bind 相关参数和值

### E. 文档/示例验收
验收标准：
- 公共头文件对新增字段有注释
- Demo 中有最少 1 处可直接复制的示例
- 说明文本没有把 `local_port_range` 写成“结束端口”

## 建议测试场景
最少覆盖以下用例，测试方法可用 Demo、自测程序或现有对象接口调用：

- 默认值：`local_port=0, local_port_range=1, outgoing_interface=NULL`
- 仅绑网卡：`outgoing_interface="本机有效网卡名"`
- 仅绑本地 IP：`outgoing_interface="本机有效 IP"`
- 仅绑单端口：`local_port=40000, local_port_range=1`
- 绑端口范围：`local_port=40000, local_port_range=10`
- 端口范围越界：`local_port=65535, local_port_range=2`
- 非法空字符串网卡：`outgoing_interface=""`
- 非法 range：`local_port=0, local_port_range=10`
- 错误网卡名：触发 `CURLE_INTERFACE_FAILED`
- 协商路径验证：在 `auth_switch = OBS_NEGOTIATION_TYPE` 下验证新参数仍生效

## 边界与非目标
本次不做以下事情，避免 minimax 过度设计：

- 不支持“起始端口 + 结束端口”形式
- 不新增 setter/getter API
- 不接 OBS.ini
- 不接环境变量
- 不新增 DNS 绑定能力
- 不为 Windows/Linux 分别设计不同对外接口
- 不新增新的 `obs_status` 枚举项
- 不做自动回退逻辑，比如绑定失败后自动改为不绑定继续请求

## 重要假设
- 客户所说“绑定请求时的端口或者端口范围”指本地源端口，不是远端服务端口
- 下游接受因 `obs_http_request_option` 扩展而带来的重新编译要求
- `outgoing_interface` 采用 libcurl 透传语义，这是本次风险最低、行为最稳定的实现方式
