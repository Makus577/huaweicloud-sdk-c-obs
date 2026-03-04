#
# 简化版Makefile - 国密+双向认证测试场景
#

CC = gcc
CFLAGS = -Wall -g -O0
INCLUDES = -I. -I../inc
LIBS = -lssl -lcrypto

# 输出目录
OUTDIR = build

# 测试框架
FRAMEWORK = ssl_gm_test_framework.c

# 场景源文件和目标
SCENARIO1 = test_scenario_1_standard_tls
SCENARIO2 = test_scenario_2_gm_one_way
SCENARIO3 = test_scenario_3_gm_mutual_dual_cert
SCENARIO4 = test_scenario_4_gm_cipher_suite

# 默认目标: 编译所有
all: $(OUTDIR)/$(SCENARIO1) $(OUTDIR)/$(SCENARIO2) $(OUTDIR)/$(SCENARIO3) $(OUTDIR)/$(SCENARIO4)
	@echo "编译完成! 可执行文件在 $(OUTDIR)/ 目录"

# 创建输出目录
$(OUTDIR):
	@mkdir -p $(OUTDIR)

# 场景1: 标准TLS双向认证
$(OUTDIR)/$(SCENARIO1): $(SCENARIO1).c $(FRAMEWORK) | $(OUTDIR)
	@echo "编译场景1: 标准TLS双向认证..."
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LIBS)

# 场景2: 国密单向认证
$(OUTDIR)/$(SCENARIO2): $(SCENARIO2).c $(FRAMEWORK) | $(OUTDIR)
	@echo "编译场景2: 国密单向认证..."
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LIBS)

# 场景3: 国密双向双证书
$(OUTDIR)/$(SCENARIO3): $(SCENARIO3).c $(FRAMEWORK) | $(OUTDIR)
	@echo "编译场景3: 国密双向双证书..."
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LIBS)

# 场景4: 国密密码套件配置
$(OUTDIR)/$(SCENARIO4): $(SCENARIO4).c $(FRAMEWORK) | $(OUTDIR)
	@echo "编译场景4: 国密密码套件配置..."
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LIBS)

#==============================================================================
# 单独编译和运行
#==============================================================================

# 场景1
scenario1: $(OUTDIR)/$(SCENARIO1)
run1: scenario1
	@./$(OUTDIR)/$(SCENARIO1)

# 场景2
scenario2: $(OUTDIR)/$(SCENARIO2)
run2: scenario2
	@./$(OUTDIR)/$(SCENARIO2)

# 场景3
scenario3: $(OUTDIR)/$(SCENARIO3)
run3: scenario3
	@./$(OUTDIR)/$(SCENARIO3)

# 场景4
scenario4: $(OUTDIR)/$(SCENARIO4)
run4: scenario4
	@./$(OUTDIR)/$(SCENARIO4)

# 运行所有场景
run: all
	@echo "========================================"
	@echo "运行场景1: 标准TLS双向认证测试"
	@echo "========================================"
	@./$(OUTDIR)/$(SCENARIO1) || true
	@echo ""
	@echo "========================================"
	@echo "运行场景2: 国密单向认证测试"
	@echo "========================================"
	@./$(OUTDIR)/$(SCENARIO2) || true
	@echo ""
	@echo "========================================"
	@echo "运行场景3: 国密双向双证书测试"
	@echo "========================================"
	@./$(OUTDIR)/$(SCENARIO3) || true
	@echo ""
	@echo "========================================"
	@echo "运行场景4: 国密密码套件配置测试"
	@echo "========================================"
	@./$(OUTDIR)/$(SCENARIO4) || true

#==============================================================================
# 清理
#==============================================================================

.PHONY: clean
clean:
	@echo "清理编译生成的文件..."
	@rm -rf $(OUTDIR)
	@echo "清理完成!"

#==============================================================================
# 帮助
#==============================================================================

.PHONY: help
help:
	@echo "=============================================================================="
	@echo "  国密+双向认证测试场景编译系统"
	@echo "=============================================================================="
	@echo ""
	@echo "【编译命令】"
	@echo "  make all          编译所有场景"
	@echo "  make scenario1    编译场景1: 标准TLS双向认证"
	@echo "  make scenario2    编译场景2: 国密单向认证"
	@echo "  make scenario3    编译场景3: 国密双向双证书"
	@echo "  make scenario4    编译场景4: 国密密码套件配置"
	@echo ""
	@echo "【运行命令】"
	@echo "  make run          编译并运行所有场景"
	@echo "  make run1         编译并运行场景1"
	@echo "  make run2         编译并运行场景2"
	@echo "  make run3         编译并运行场景3"
	@echo "  make run4         编译并运行场景4"
	@echo ""
	@echo "【其他命令】"
	@echo "  make clean        清理编译生成的文件"
	@echo "  make help         显示此帮助信息"
	@echo "=============================================================================="
