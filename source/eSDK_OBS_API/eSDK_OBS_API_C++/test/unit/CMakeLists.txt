#**********************************************************************************
# Copyright 2024 Huawei Technologies Co.,Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#**********************************************************************************

# CMakeLists.txt for GM + Mutual Auth Unit Tests (Pure C version)
#
# This CMake file builds the C unit test suite for:
# - GM (National Cryptography) mode functionality
# - Mutual authentication (mTLS)
# - Password lazy loading callback
# - CA certificate configuration

cmake_minimum_required(VERSION 3.10)
project(gm_mutual_auth_test C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build options
option(ENABLE_COVERAGE "Enable code coverage reporting" OFF)
option(ENABLE_ASAN "Enable Address Sanitizer" OFF)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Coverage flags
if(ENABLE_COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov")
endif()

# Address Sanitizer flags
if(ENABLE_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
endif()

# Find required packages
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CURL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Test source files
set(TEST_SOURCES
    main.c
    src/test_framework.c
    src/test_mocks.c
    stubs/sdk_stubs.c
    tests/test_mutual_auth.c
    tests/test_password_callback.c
    tests/test_gm_mode.c
    tests/test_ca_cert.c
    tests/test_integration.c
)

# Filter to only existing files
set(EXISTING_TEST_SOURCES)
foreach(src ${TEST_SOURCES})
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${src})
        list(APPEND EXISTING_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${src})
    endif()
endforeach()

# Create test executable
add_executable(${PROJECT_NAME}
    ${EXISTING_TEST_SOURCES}
)

# Link libraries
target_link_libraries(${PROJECT_NAME}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CURL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# Compiler definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE
    -DUNIT_TEST
    -D_GNU_SOURCE
)

# Enable GM support if requested
option(OBS_ENABLE_GM_SUPPORT "Enable National Cryptography (GM) support" ON)
if(OBS_ENABLE_GM_SUPPORT)
    target_compile_definitions(${PROJECT_NAME} PRIVATE -DOBS_ENABLE_GM_SUPPORT)
endif()

# Add test to ctest
add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

# Print configuration summary
message(STATUS "")
message(STATUS "GM Mutual Auth Unit Test Configuration:")
message(STATUS "  C Standard: ${CMAKE_C_STANDARD}")
message(STATUS "  Coverage: ${ENABLE_COVERAGE}")
message(STATUS "  Address Sanitizer: ${ENABLE_ASAN}")
message(STATUS "  GM Support: ${OBS_ENABLE_GM_SUPPORT}")
message(STATUS "  libcurl: ${CURL_LIBRARIES}")
message(STATUS "  OpenSSL: ${OPENSSL_LIBRARIES}")
message(STATUS "  Test Sources: ${EXISTING_TEST_SOURCES}")
message(STATUS "")
