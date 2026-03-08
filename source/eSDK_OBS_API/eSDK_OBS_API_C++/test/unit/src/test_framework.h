/*********************************************************************************
* Copyright 2024 Huawei Technologies Co.,Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* You may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software distributed
* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
* CONDITIONS OF ANY KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations under the License.
**********************************************************************************
*/

/**
 * @file test_framework.h
 * @brief Lightweight C unit testing framework for OBS SDK
 *
 * This is a minimal test framework that provides:
 * - Test case registration and execution
 * - Assertion macros
 * - Test results reporting
 * - Test fixture setup/teardown support
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Test color codes */
#define TEST_COLOR_GREEN   "\033[0;32m"
#define TEST_COLOR_RED     "\033[0;31m"
#define TEST_COLOR_YELLOW  "\033[0;33m"
#define TEST_COLOR_BLUE    "\033[0;34m"
#define TEST_COLOR_RESET   "\033[0m"

/* Color codes for terminal output */
#define TEST_COLOR_GREEN   "\033[0;32m"
#define TEST_COLOR_RED     "\033[0;31m"
#define TEST_COLOR_YELLOW  "\033[0;33m"
#define TEST_COLOR_BLUE    "\033[0;34m"
#define TEST_COLOR_RESET   "\033[0m"

/* Test result codes */
typedef enum {
    TEST_RESULT_PASS = 0,
    TEST_RESULT_FAIL = 1,
    TEST_RESULT_SKIP = 2
} test_result_t;

/* Test function type */
typedef void (*test_func_t)(void);

/* Fixture functions */
typedef void (*fixture_setup_t)(void);
typedef void (*fixture_teardown_t)(void);

/* Test case structure */
typedef struct test_case {
    const char* suite_name;
    const char* test_name;
    test_func_t test_func;
    fixture_setup_t setup;
    fixture_teardown_t teardown;
    struct test_case* next;
} test_case_t;

/* Test statistics */
typedef struct {
    int total;
    int passed;
    int failed;
    int skipped;
    double total_time;
} test_stats_t;

/* Global test registry */
extern test_case_t* g_test_registry;
extern test_stats_t g_test_stats;
extern int g_test_verbose;
extern int g_test_color;

/* Function prototypes */

/**
 * @brief Register a test case
 */
test_case_t* test_register(const char* suite, const char* name, test_func_t func);

/**
 * @brief Register a test case with fixtures
 */
test_case_t* test_register_fixture(const char* suite, const char* name,
                                     test_func_t func,
                                     fixture_setup_t setup,
                                     fixture_teardown_t teardown);

/**
 * @brief Run all registered tests
 */
int test_run_all(void);

/**
 * @brief Run a single test
 */
test_result_t test_run_one(test_case_t* test);

/**
 * @brief Print test summary
 */
void test_print_summary(void);

/**
 * @brief Print colored text to stdout
 */
void print_colored(const char* color, const char* fmt, ...);

/**
 * @brief Assert that a condition is true
 */
void test_assert_true(int condition, const char* file, int line, const char* msg);

/**
 * @brief Assert that two integers are equal
 */
void test_assert_eq_int(int expected, int actual, const char* file, int line);

/**
 * @brief Assert that two strings are equal
 */
void test_assert_eq_str(const char* expected, const char* actual, const char* file, int line);

/**
 * @brief Assert that a pointer is NULL
 */
void test_assert_null(void* ptr, const char* file, int line);

/**
 * @brief Assert that a pointer is not NULL
 */
void test_assert_not_null(void* ptr, const char* file, int line);

/**
 * @brief Skip the current test
 */
void test_skip(const char* reason, const char* file, int line);

/**
 * @brief Fail the current test
 */
void test_fail(const char* reason, const char* file, int line);

/* Convenience macros */

#define TEST_ASSERT_TRUE(cond) \
    test_assert_true((cond), __FILE__, __LINE__, #cond)

#define TEST_ASSERT_FALSE(cond) \
    test_assert_true(!(cond), __FILE__, __LINE__, "Expected false: " #cond)

#define TEST_ASSERT_EQ_INT(expected, actual) \
    test_assert_eq_int((expected), (actual), __FILE__, __LINE__)

#define TEST_ASSERT_NE_INT(expected, actual) \
    test_assert_true((expected) != (actual), __FILE__, __LINE__, \
                     "Expected not equal")

#define TEST_ASSERT_EQ_STR(expected, actual) \
    test_assert_eq_str((expected), (actual), __FILE__, __LINE__)

#define TEST_ASSERT_NULL(ptr) \
    test_assert_null((ptr), __FILE__, __LINE__)

#define TEST_ASSERT_NOT_NULL(ptr) \
    test_assert_not_null((ptr), __FILE__, __LINE__)

#define TEST_SKIP(reason) \
    test_skip((reason), __FILE__, __LINE__)

#define TEST_FAIL(reason) \
    test_fail((reason), __FILE__, __LINE__)

/* Forward declaration of registration function */
typedef void (*test_register_func_t)(void);

/* Test registration macros */

#define TEST(suite, name) \
    static void test_##suite##_##name(void); \
    static void __attribute__((constructor)) test_register_##suite##_##name(void) { \
        test_register(#suite, #name, test_##suite##_##name); \
    } \
    static void test_##suite##_##name(void)

#define TEST_F(suite, name) \
    static void test_##suite##_##name(void); \
    static void setup_##suite##_##name(void); \
    static void teardown_##suite##_##name(void); \
    static void __attribute__((constructor)) test_register_##suite##_##name(void) { \
        test_register_fixture(#suite, #name, \
                              test_##suite##_##name, \
                              setup_##suite##_##name, \
                              teardown_##suite##_##name); \
    } \
    static void setup_##suite##_##name(void) \
    { (void)0; } \
    static void teardown_##suite##_##name(void) \
    { (void)0; } \
    static void test_##suite##_##name(void)

#ifdef __cplusplus
}
#endif

#endif /* TEST_FRAMEWORK_H */
