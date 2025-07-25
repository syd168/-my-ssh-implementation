#!/bin/bash

echo "=== SSH通信项目 - 所有8个阶段完整测试 ==="
echo "测试开始时间: $(date)"
echo ""

# 检查构建状态
echo "🔧 检查构建状态..."
if [ ! -d "build" ]; then
    echo "❌ 构建目录不存在，正在构建项目..."
    make clean && make all
fi

test_results=()
all_passed=true

# 测试函数
run_stage_test() {
    local stage=$1
    local test_name=$2
    local test_command=$3
    
    echo ""
    echo "📋 测试阶段 $stage: $test_name"
    echo "-------------------------------------------"
    
    if eval "$test_command"; then
        echo "✅ 阶段 $stage 测试通过"
        test_results+=("✅ 阶段 $stage: $test_name - 通过")
        return 0
    else
        echo "❌ 阶段 $stage 测试失败"
        test_results+=("❌ 阶段 $stage: $test_name - 失败")
        all_passed=false
        return 1
    fi
}

# 阶段1: 基础网络通信测试
run_stage_test "1" "基础网络通信" "timeout 10s ./test_stage1.sh"

# 阶段2: 协议版本协商测试  
run_stage_test "2" "协议版本协商" "timeout 10s ./test_stage2_simple.sh"

# 阶段3: 密钥交换测试
run_stage_test "3" "密钥交换实现" "timeout 15s ./test_stage3.sh"

# 阶段4: 加密算法测试
run_stage_test "4" "加密算法实现" "timeout 10s ./test_stage4.sh"

# 阶段5: SSH消息格式测试
run_stage_test "5" "SSH消息格式" "make test-packet > /dev/null 2>&1"

# 阶段6: 用户认证测试
run_stage_test "6" "用户认证实现" "make test-auth > /dev/null 2>&1"

# 阶段7: 安全通道测试
run_stage_test "7" "安全通道建立" "make test-channel > /dev/null 2>&1"

# 阶段8: 应用层通信测试
run_stage_test "8" "应用层通信" "make test-app > /dev/null 2>&1"

echo ""
echo "============================================="
echo "📊 测试结果汇总"
echo "============================================="

for result in "${test_results[@]}"; do
    echo "$result"
done

echo ""
echo "📈 项目统计信息:"
echo "  - 总代码行数: $(find src -name '*.c' -o -name '*.h' | xargs wc -l | tail -1 | awk '{print $1}')"
echo "  - 源文件数量: $(find src -name '*.c' -o -name '*.h' | wc -l)"
echo "  - 可执行程序: $(ls build/ | wc -l)"
echo "  - 测试脚本数: $(ls test_stage*.sh | wc -l)"

echo ""
if $all_passed; then
    echo "🎉 恭喜！所有8个阶段测试全部通过！"
    echo ""
    echo "📖 使用说明:"
    echo "  阶段1-4 可以使用对应的服务器/客户端程序："
    echo "    make run-server       # 阶段1基础服务器"
    echo "    make run-ssh-server   # 阶段2协议协商服务器"  
    echo "    make run-ssh-server-v3 # 阶段3密钥交换服务器"
    echo "    make run-ssh-server-v4 # 阶段4加密通信服务器"
    echo ""
    echo "  阶段5-8 使用独立的测试程序："
    echo "    make test-packet      # 阶段5 SSH消息格式测试"
    echo "    make test-auth        # 阶段6 用户认证测试"
    echo "    make test-channel     # 阶段7 安全通道测试" 
    echo "    make test-app         # 阶段8 应用层通信测试"
    echo ""
    echo "💡 提示: 完整的SSH实现已集成在ssh_server_v3/ssh_client_v3中"
    exit 0
else
    echo "❌ 部分阶段测试失败，请检查相关实现"
    echo ""
    echo "🔍 调试建议:"
    echo "  1. 检查编译错误: make clean && make all"
    echo "  2. 查看详细日志: 运行对应的test_stageX.sh脚本"
    echo "  3. 检查进程冲突: 确保没有其他SSH进程占用端口"
    exit 1
fi
