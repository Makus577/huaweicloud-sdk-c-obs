# 国密+双向认证UT测试框架

## 项目概述

本项目是针对华为云OBS C SDK的国密(GM)和双向认证(mTLS)功能的单元测试框架。使用纯C语言实现，不依赖C++的gtest。

## 目录结构

```
test/unit/
├── CMakeLists.txt          # 构建配置
├── README.md               # 本文档
├── src/                    # 测试框架核心代码
│   ├── test_framework.c    # 测试框架实现
│   ├── test_framework.h    # 测试框架头文件
│   ├── test_mocks.c        # Mock实现
│   ├── test_mocks.h        # Mock头文件
│   └── test_types.h        # 类型定义
├── tests/                  # 测试用例
│   ├── test_mutual_auth.c      # 双向认证测试(7个)
│   ├── test_password_callback.c # 密码回调测试(5个)
│   ├── test_gm_mode.c          # 国密模式测试(6个)
│   ├── test_ca_cert.c          # CA证书测试(3个)
│   └── test_integration.c      # 集成测试(3个)
├── stubs/                  # SDK函数桩实现
│   └── sdk_stubs.c         # 被测函数的桩实现
└── build/                  # 构建输出目录
```

## 测试框架特性

### 1. 核心功能
- **测试注册**: 自动注册测试用例
- **断言支持**: 丰富的断言宏(TEST_ASSERT_*)
- **结果输出**: 彩色终端输出，清晰的测试报告
- **覆盖率**: 支持gcov代码覆盖率统计

### 2. Mock框架
- **Curl Mock**: 模拟curl_easy_setopt等函数
- **OpenSSL Mock**: 模拟SSL_CTX_set_*等函数
- **调用统计**: 记录函数调用次数和参数

### 3. 测试套件

| 套件 | 测试数 | 覆盖功能 |
|------|--------|----------|
| MutualAuth | 7 | 双向认证开关、证书路径验证、错误处理 |
| PasswordCallback | 5 | 密码延迟获取、回调执行、错误处理 |
| GMMode | 6 | 国密模式开关、双证书、Tongsuo检测 |
| CACertConfig | 3 | CA证书路径、证书信息、验证开关 |
| Integration | 3 | 完整流程、错误恢复、资源清理 |

## 编译运行

### 编译
```bash
cd /root/huaweicloud-sdk-c-obs/source/eSDK_OBS_API/eSDK_OBS_API_C++/test/unit
mkdir -p build && cd build
cmake ..
make -j4
```

### 运行测试
```bash
# 运行所有测试
./gm_mutual_auth_test

# 详细输出
./gm_mutual_auth_test -v

# 运行特定测试(通过过滤)
./gm_mutual_auth_test --filter=MutualAuth
```

### 代码覆盖率
```bash
cmake -DENABLE_COVERAGE=ON ..
make -j4
./gm_mutual_auth_test
make coverage
```

## 后续优化建议

1. **链接真实SDK**: 当前使用桩函数，后续可链接真实SDK进行集成测试
2. **添加更多边界测试**: 补充边界条件和异常情况测试
3. **性能测试**: 添加性能基准测试
4. **CI/CD集成**: 集成到持续集成流程

## 作者

华为云OBS SDK开发团队

## 许可证

Apache License 2.0
