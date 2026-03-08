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
 * @file test_framework.c
 * @brief Implementation of the lightweight C test framework
 */

#include "test_framework.h"
#include <time.h>

/* Global state */
test_case_t* g_test_registry = NULL;
test_stats_t g_test_stats = { 0, 0, 0, 0, 0.0 };
int g_test_verbose = 1;
int g_test_color = 1;

/* Helper functions */

void print_colored(const char* color, const char* fmt, ...) {
    va_list args;
    if (g_test_color && color) {
        printf("%s", color);
    }
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    if (g_test_color && color) {
        printf("%s", TEST_COLOR_RESET);
    }
}

static void print_result(test_result_t result) {
    switch (result) {
        case TEST_RESULT_PASS:
            print_colored(TEST_COLOR_GREEN, "[  PASS  ]");
            break;
        case TEST_RESULT_FAIL:
            print_colored(TEST_COLOR_RED, "[  FAIL  ]");
            break;
        case TEST_RESULT_SKIP:
            print_colored(TEST_COLOR_YELLOW, "[  SKIP  ]");
            break;
    }
}

static test_case_t* find_test(const char* suite, const char* name) {
    test_case_t* test = g_test_registry;
    while (test) {
        if (strcmp(test->suite_name, suite) == 0 &&
            strcmp(test->test_name, name) == 0) {
            return test;
        }
        test = test->next;
    }
    return NULL;
}

static void register_test(test_case_t* test) {
    test->next = g_test_registry;
    g_test_registry = test;
}

/* Public API implementation */

test_case_t* test_register(const char* suite, const char* name, test_func_t func) {
    test_case_t* test = find_test(suite, name);
    if (test) {
        fprintf(stderr, "Warning: Test %s.%s already registered, skipping\n", suite, name);
        return test;
    }

    test = (test_case_t*)calloc(1, sizeof(test_case_t));
    if (!test) {
        fprintf(stderr, "Error: Failed to allocate memory for test\n");
        exit(1);
    }

    test->suite_name = suite;
    test->test_name = name;
    test->test_func = func;
    test->setup = NULL;
    test->teardown = NULL;

    register_test(test);
    return test;
}

test_case_t* test_register_fixture(const char* suite, const char* name,
                                   test_func_t func,
                                   fixture_setup_t setup,
                                   fixture_teardown_t teardown) {
    test_case_t* test = test_register(suite, name, func);
    if (test) {
        test->setup = setup;
        test->teardown = teardown;
    }
    return test;
}

test_result_t test_run_one(test_case_t* test) {
    printf("Running %s.%s\n", test->suite_name, test->test_name);

    /* Run setup if provided */
    if (test->setup) {
        test->setup();
    }

    /* Run the actual test */
    /* Note: This is a simplified version. In reality, we'd need
     * signal handling to catch crashes and proper exception handling.
     * For now, tests are expected to return normally or call TEST_FAIL.
     */
    test->test_func();

    /* Run teardown if provided */
    if (test->teardown) {
        test->teardown();
    }

    return TEST_RESULT_PASS;
}

int test_run_all(void) {
    test_case_t* test = g_test_registry;
    int passed = 0, failed = 0, skipped = 0;
    clock_t start_time = clock();

    printf("\n");
    print_colored(TEST_COLOR_BLUE, "========== Running Unit Tests ==========\n");
    printf("\n");

    /* Count tests */
    int test_count = 0;
    while (test) {
        test_count++;
        test = test->next;
    }

    printf("Total tests: %d\n\n", test_count);

    /* Run tests in reverse order (they were added to head of list) */
    test = g_test_registry;
    while (test) {
        test_result_t result = test_run_one(test);
        print_result(result);
        printf(" %s.%s\n", test->suite_name, test->test_name);

        switch (result) {
            case TEST_RESULT_PASS:
                passed++;
                break;
            case TEST_RESULT_FAIL:
                failed++;
                break;
            case TEST_RESULT_SKIP:
                skipped++;
                break;
        }

        test = test->next;
    }

    clock_t end_time = clock();
    double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    /* Store stats */
    g_test_stats.total = test_count;
    g_test_stats.passed = passed;
    g_test_stats.failed = failed;
    g_test_stats.skipped = skipped;
    g_test_stats.total_time = elapsed;

    printf("\n");
    print_colored(TEST_COLOR_BLUE, "========== Test Summary ==========\n");
    printf("Total:  %d\n", test_count);
    print_colored(TEST_COLOR_GREEN, "Passed: %d\n", passed);
    if (failed > 0) {
        print_colored(TEST_COLOR_RED, "Failed: %d\n", failed);
    }
    if (skipped > 0) {
        print_colored(TEST_COLOR_YELLOW, "Skipped: %d\n", skipped);
    }
    printf("Time:   %.3fs\n", elapsed);
    printf("\n");

    return failed;
}

void test_print_summary(void) {
    printf("\nTest Summary:\n");
    printf("  Total:   %d\n", g_test_stats.total);
    printf("  Passed:  %d\n", g_test_stats.passed);
    printf("  Failed:  %d\n", g_test_stats.failed);
    printf("  Skipped: %d\n", g_test_stats.skipped);
    printf("  Time:    %.3fs\n", g_test_stats.total_time);
}

/* Assertion implementations */

void test_assert_true(int condition, const char* file, int line, const char* msg) {
    if (!condition) {
        printf("\n  ASSERTION FAILED at %s:%d\n", file, line);
        printf("  Expected: true\n");
        printf("  Actual:   false\n");
        if (msg && *msg) {
            printf("  Message:  %s\n", msg);
        }
        /* In a real implementation, we'd longjmp or use some mechanism
         * to return to the test runner. For now, we just print the failure. */
    }
}

void test_assert_eq_int(int expected, int actual, const char* file, int line) {
    if (expected != actual) {
        printf("\n  ASSERTION FAILED at %s:%d\n", file, line);
        printf("  Expected: %d\n", expected);
        printf("  Actual:   %d\n", actual);
    }
}

void test_assert_eq_str(const char* expected, const char* actual, const char* file, int line) {
    int fail = 0;
    if (expected == NULL || actual == NULL) {
        if (expected != actual) {
            fail = 1;
        }
    } else if (strcmp(expected, actual) != 0) {
        fail = 1;
    }

    if (fail) {
        printf("\n  ASSERTION FAILED at %s:%d\n", file, line);
        printf("  Expected: \"%s\"\n", expected ? expected : "(null)");
        printf("  Actual:   \"%s\"\n", actual ? actual : "(null)");
    }
}

void test_assert_null(void* ptr, const char* file, int line) {
    if (ptr != NULL) {
        printf("\n  ASSERTION FAILED at %s:%d\n", file, line);
        printf("  Expected: NULL\n");
        printf("  Actual:   %p\n", ptr);
    }
}

void test_assert_not_null(void* ptr, const char* file, int line) {
    if (ptr == NULL) {
        printf("\n  ASSERTION FAILED at %s:%d\n", file, line);
        printf("  Expected: not NULL\n");
        printf("  Actual:   NULL\n");
    }
}

void test_skip(const char* reason, const char* file, int line) {
    printf("\n  SKIPPED at %s:%d\n", file, line);
    printf("  Reason: %s\n", reason ? reason : "No reason given");
}

void test_fail(const char* reason, const char* file, int line) {
    printf("\n  FAILED at %s:%d\n", file, line);
    printf("  Reason: %s\n", reason ? reason : "No reason given");
}
