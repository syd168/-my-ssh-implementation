#!/bin/bash

echo "=== SSH通信项目 - 所有阶段验证脚本 ==="
echo "检查时间: $(date)"
echo ""

# 检查构建目录
if [ ! -d "build" ]; then
    echo "❌ 构建目录不存在，请先运行 'make all'"
    exit 1
fi

echo "📋 检查所有阶段的可执行文件："
echo ""

stages=(
    "阶段1:ssh_server:基础服务器"
    "阶段1:ssh_client:基础客户端"
    "阶段2:ssh_server_v2:协议协商服务器"
    "阶段2:ssh_client_v2:协议协商客户端"
    "阶段3:ssh_server_v3:密钥交换服务器"
    "阶段3:ssh_client_v3:密钥交换客户端"
    "阶段4:ssh_server_v4:加密通信服务器"
    "阶段4:ssh_client_v4:加密通信客户端"
)

all_good=true

for stage_info in "${stages[@]}"; do
    IFS=':' read -r stage_name binary_name description <<< "$stage_info"
    
    if [ -x "build/$binary_name" ]; then
        size=$(ls -lh "build/$binary_name" | awk '{print $5}')
        echo "✅ $stage_name - $description ($binary_name) - 大小: $size"
    else
        echo "❌ $stage_name - $description ($binary_name) - 缺失或不可执行"
        all_good=false
    fi
done

echo ""

if $all_good; then
    echo "🎉 所有SSH阶段都已成功构建！"
    echo ""
    echo "📖 使用说明："
    echo "  make run-server      # 运行阶段1基础服务器"
    echo "  make run-client      # 运行阶段1基础客户端"
    echo "  make run-ssh-server  # 运行阶段2协议协商服务器"
    echo "  make run-ssh-client  # 运行阶段2协议协商客户端"
    echo "  make run-ssh-server-v3  # 运行阶段3密钥交换服务器"
    echo "  make run-ssh-client-v3  # 运行阶段3密钥交换客户端"
    echo "  make run-ssh-server-v4  # 运行阶段4加密通信服务器"
    echo "  make run-ssh-client-v4  # 运行阶段4加密通信客户端"
    echo ""
    echo "💡 提示: 在两个终端中分别运行服务器和客户端来测试通信"
else
    echo "❌ 部分SSH阶段构建失败，请检查编译错误"
    exit 1
fi
