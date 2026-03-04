cmake_minimum_required(VERSION 3.10)
project(ssl_config_tests)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g -O0")

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/../inc)

# 查找OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# OBS SDK 桩实现
add_library(obs_sdk_stub obs_sdk_stub.c)
target_link_libraries(obs_sdk_stub ${OPENSSL_LIBRARIES})

# GM测试框架库
add_library(ssl_gm_test_framework ssl_gm_test_framework.c)
target_link_libraries(ssl_gm_test_framework obs_sdk_stub ${OPENSSL_LIBRARIES})

# 场景1: 标准TLS双向认证测试
add_executable(test_scenario_1_standard_tls test_scenario_1_standard_tls.c)
target_link_libraries(test_scenario_1_standard_tls ssl_gm_test_framework obs_sdk_stub ${OPENSSL_LIBRARIES})

# 场景2: 国密单向认证测试
add_executable(test_scenario_2_gm_one_way test_scenario_2_gm_one_way.c)
target_link_libraries(test_scenario_2_gm_one_way ssl_gm_test_framework obs_sdk_stub ${OPENSSL_LIBRARIES})

# 场景3: 国密双向双证书测试
add_executable(test_scenario_3_gm_mutual_dual_cert test_scenario_3_gm_mutual_dual_cert.c)
target_link_libraries(test_scenario_3_gm_mutual_dual_cert ssl_gm_test_framework obs_sdk_stub ${OPENSSL_LIBRARIES})

# 场景4: 国密密码套件配置测试
add_executable(test_scenario_4_gm_cipher_suite test_scenario_4_gm_cipher_suite.c)
target_link_libraries(test_scenario_4_gm_cipher_suite ssl_gm_test_framework obs_sdk_stub ${OPENSSL_LIBRARIES})

# 测试套件
enable_testing()
add_test(NAME test_scenario_1_standard_tls COMMAND test_scenario_1_standard_tls)
add_test(NAME test_scenario_2_gm_one_way COMMAND test_scenario_2_gm_one_way)
add_test(NAME test_scenario_3_gm_mutual_dual_cert COMMAND test_scenario_3_gm_mutual_dual_cert)
add_test(NAME test_scenario_4_gm_cipher_suite COMMAND test_scenario_4_gm_cipher_suite)
