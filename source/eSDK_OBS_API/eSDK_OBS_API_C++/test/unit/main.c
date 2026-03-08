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
 * @file main.c
 * @brief Main entry point for GM + Mutual Auth unit tests
 *
 * Usage: ./gm_mutual_auth_test [options]
 *
 * Options:
 *   -v, --verbose    Enable verbose output
 *   -c, --color      Enable colored output (default: auto)
 *   -f, --filter     Run only tests matching pattern
 *   -h, --help       Show help message
 *
 * Examples:
 *   ./gm_mutual_auth_test -v
 *   ./gm_mutual_auth_test --filter=MutualAuth
 *   ./gm_mutual_auth_test --filter=GMMode
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "test_framework.h"

/* External test suites - declared in test files */
extern void register_mutual_auth_tests(void);
extern void register_password_callback_tests(void);
extern void register_gm_mode_tests(void);
extern void register_ca_cert_tests(void);
extern void register_integration_tests(void);

/* Command line options */
static struct option long_options[] = {
    {"verbose", no_argument, 0, 'v'},
    {"color", required_argument, 0, 'c'},
    {"filter", required_argument, 0, 'f'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

static void print_usage(const char* prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("\n");
    printf("GM + Mutual Auth Unit Tests\n");
    printf("\n");
    printf("Options:\n");
    printf("  -v, --verbose          Enable verbose output\n");
    printf("  -c, --color=MODE     Enable colored output (auto/always/never)\n");
    printf("  -f, --filter=PATTERN Run only tests matching pattern\n");
    printf("  -h, --help           Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -v                    # Run all tests with verbose output\n", prog_name);
    printf("  %s --filter=MutualAuth   # Run only mutual auth tests\n", prog_name);
    printf("  %s --filter=GMMode       # Run only GM mode tests\n", prog_name);
    printf("\n");
}

static void parse_args(int argc, char** argv) {
    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "vc:f:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'v':
                g_test_verbose = 1;
                break;
            case 'c':
                if (strcmp(optarg, "never") == 0) {
                    g_test_color = 0;
                } else if (strcmp(optarg, "always") == 0) {
                    g_test_color = 1;
                }
                /* "auto" is default */
                break;
            case 'f':
                /* Filter is not fully implemented in this simple framework */
                printf("Filter option not fully implemented yet: %s\n", optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                exit(1);
        }
    }
}

int main(int argc, char** argv) {
    /* Parse command line arguments */
    parse_args(argc, argv);

    /* Print banner */
    printf("\n");
    print_colored(TEST_COLOR_BLUE, "========================================\n");
    print_colored(TEST_COLOR_BLUE, "  GM + Mutual Auth Unit Tests\n");
    print_colored(TEST_COLOR_BLUE, "========================================\n");
    printf("\n");

    /* Register all test suites */
    printf("Registering test suites...\n");
    register_mutual_auth_tests();
    register_password_callback_tests();
    register_gm_mode_tests();
    register_ca_cert_tests();
    register_integration_tests();

    /* Run all tests */
    int result = test_run_all();

    /* Print final result */
    printf("\n");
    if (result == 0) {
        print_colored(TEST_COLOR_GREEN, "All tests passed!\n");
    } else {
        print_colored(TEST_COLOR_RED, "Some tests failed!\n");
    }
    printf("\n");

    return result;
}
