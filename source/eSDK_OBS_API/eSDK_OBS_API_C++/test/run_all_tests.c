/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 *
 * Test Runner for GM + Mutual Authentication Test Scenarios
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define NUM_SCENARIOS 4

typedef struct {
    const char *name;
    const char *executable;
    const char *description;
} test_scenario_t;

static test_scenario_t scenarios[NUM_SCENARIOS] = {
    {
        "场景1: 标准TLS双向认证",
        "./test_scenario_1_standard_tls",
        "测试标准TLS双向认证配置"
    },
    {
        "场景2: 国密单向认证",
        "./test_scenario_2_gm_one_way",
        "测试国密单向认证配置"
    },
    {
        "场景3: 国密双向双证书",
        "./test_scenario_3_gm_mutual_dual_cert",
        "测试国密双向双证书配置"
    },
    {
        "场景4: 国密密码套件配置",
        "./test_scenario_4_gm_cipher_suite",
        "测试国密密码套件配置"
    }
};

static void print_separator(void) {
    printf("\n");
    for (int i = 0; i < 80; i++) printf("=");
    printf("\n\n");
}

static int run_test_scenario(int index) {
    test_scenario_t *scenario = &scenarios[index];

    print_separator();
    printf("【%s】\n", scenario->name);
    printf("描述: %s\n", scenario->description);
    printf("执行: %s\n\n", scenario->executable);

    // 检查可执行文件是否存在
    if (access(scenario->executable, X_OK) != 0) {
        printf("错误: 找不到可执行文件 %s\n", scenario->executable);
        printf("请先编译测试程序: cd build && make\n");
        return -1;
    }

    // 执行测试
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork failed");
        return -1;
    }

    if (pid == 0) {
        // 子进程
        execl(scenario->executable, scenario->executable, NULL);
        perror("execl failed");
        exit(1);
    } else {
        // 父进程
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            printf("\n测试完成，退出码: %d\n", exit_code);
            return exit_code;
        } else {
            printf("\n测试异常终止\n");
            return -1;
        }
    }
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("\n");
    for (int i = 0; i < 80; i++) printf("#");
    printf("\n");
    printf("# 国密+双向认证测试执行器\n");
    printf("# GM + Mutual Authentication Test Runner\n");
    for (int i = 0; i < 80; i++) printf("#");
    printf("\n");

    int total_tests = NUM_SCENARIOS;
    int passed_tests = 0;
    int failed_tests = 0;

    for (int i = 0; i < NUM_SCENARIOS; i++) {
        int result = run_test_scenario(i);
        if (result == 0) {
            passed_tests++;
        } else {
            failed_tests++;
        }
    }

    print_separator();
    printf("测试摘要\n");
    printf("========\n");
    printf("总测试数: %d\n", total_tests);
    printf("通过: %d\n", passed_tests);
    printf("失败: %d\n", failed_tests);
    printf("\n");

    if (failed_tests == 0) {
        printf("所有测试通过!\n");
        return 0;
    } else {
        printf("部分测试失败，请检查输出详情。\n");
        return 1;
    }
}
