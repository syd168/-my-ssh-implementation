#!/bin/bash

echo "==============================================="
echo "🚀 SSH手动测试演示脚本"
echo "==============================================="
echo

# 函数：等待用户按键
wait_for_key() {
    echo "按任意键继续..."
    read -n 1 -s
    echo
}

# 函数：清理进程
cleanup() {
    echo "🧹 清理SSH服务器进程..."
    pkill -f ssh_server 2>/dev/null
    sleep 1
}

# 函数：检查服务器状态
check_server() {
    local version=$1
    echo "🔍 检查SSH服务器${version}状态..."
    
    if ps aux | grep -q "ssh_server${version}" | grep -v grep; then
        echo "✅ 服务器正在运行"
    else
        echo "❌ 服务器未运行"
        return 1
    fi
    
    if netstat -tlnp 2>/dev/null | grep -q ":2222"; then
        echo "✅ 端口2222正在监听"
    else
        echo "❌ 端口2222未监听"
        return 1
    fi
    return 0
}

# 函数：演示服务器启动
demo_server_start() {
    local version=$1
    local description=$2
    
    echo "📡 演示：启动${description}"
    echo "命令：./build/ssh_server${version}"
    echo
    
    cleanup
    
    ./build/ssh_server${version} > demo_server${version}.log 2>&1 &
    local server_pid=$!
    
    echo "服务器PID: $server_pid"
    sleep 2
    
    if check_server "${version}"; then
        echo "✅ ${description}启动成功！"
        echo
        echo "📋 服务器日志（前5行）："
        head -5 demo_server${version}.log
        echo
        return 0
    else
        echo "❌ ${description}启动失败！"
        return 1
    fi
}

# 函数：演示客户端连接说明
demo_client_instructions() {
    local version=$1
    local description=$2
    
    echo "💻 客户端连接说明"
    echo "================="
    echo
    echo "现在你可以在另一个终端中运行："
    echo "    ./build/ssh_client${version}"
    echo
    echo "期待的行为："
    case $version in
        "")
            echo "• 显示 'Connected to server'"
            echo "• 可以发送文本消息"
            echo "• 输入 'quit' 断开连接"
            ;;
        "_v2")
            echo "• 显示SSH版本交换过程"
            echo "• 完成协议版本协商"
            echo "• 显示 'Connected to SSH server'"
            echo "• 可以发送消息"
            ;;
        "_v3")
            echo "• 完成SSH版本协商"
            echo "• 执行密钥交换（可能有警告）"
            echo "• 用户认证"
            echo "• 可以执行命令：ls, pwd, echo等"
            echo "• 输入 'exit' 断开连接"
            ;;
    esac
    echo
}

# 函数：监控服务器日志
monitor_server_log() {
    local version=$1
    echo "📊 实时监控服务器日志 (按Ctrl+C停止)："
    echo "==============================================="
    tail -f demo_server${version}.log
}

echo "本脚本将演示SSH项目的手动测试过程"
echo "你需要准备两个终端窗口进行测试"
echo
wait_for_key

# 演示阶段1
echo "🏗️  阶段一：基础网络通信测试"
echo "================================"
if demo_server_start "" "基础SSH服务器"; then
    demo_client_instructions "" "基础网络通信"
    echo "想要查看服务器实时日志吗？(y/n)"
    read -n 1 answer
    echo
    if [[ $answer == "y" || $answer == "Y" ]]; then
        monitor_server_log ""
    fi
fi

wait_for_key

# 演示阶段2
echo "🤝 阶段二：协议版本协商测试"
echo "============================="
if demo_server_start "_v2" "SSH协议版本协商服务器"; then
    demo_client_instructions "_v2" "协议版本协商"
    echo "想要查看服务器实时日志吗？(y/n)"
    read -n 1 answer
    echo
    if [[ $answer == "y" || $answer == "Y" ]]; then
        monitor_server_log "_v2"
    fi
fi

wait_for_key

# 演示阶段3
echo "🔐 阶段三：完整SSH协议测试（推荐）"
echo "=================================="
if demo_server_start "_v3" "完整SSH服务器"; then
    demo_client_instructions "_v3" "完整SSH协议"
    echo "这是最完整和稳定的版本，建议重点测试！"
    echo
    echo "想要查看服务器实时日志吗？(y/n)"
    read -n 1 answer
    echo
    if [[ $answer == "y" || $answer == "Y" ]]; then
        monitor_server_log "_v3"
    fi
fi

wait_for_key

echo "🧪 功能模块独立测试"
echo "==================="
echo "以下模块测试不需要手动启动服务器："
echo

echo "📦 阶段五：SSH消息格式测试"
echo "命令：make test-packet"
echo

echo "🔐 阶段六：用户认证测试"
echo "命令：make test-auth"
echo

echo "🔗 阶段七：通道管理测试"
echo "命令：make test-channel"
echo

echo "🚀 阶段八：应用层通信测试"
echo "命令：make test-app"
echo

echo "想要运行所有功能模块测试吗？(y/n)"
read -n 1 answer
echo

if [[ $answer == "y" || $answer == "Y" ]]; then
    echo "🧪 运行功能模块测试..."
    echo
    
    echo "📦 测试SSH消息格式..."
    make test-packet
    echo
    
    echo "🔐 测试用户认证..."
    make test-auth
    echo
    
    echo "🔗 测试通道管理..."
    make test-channel
    echo
    
    echo "🚀 测试应用层通信..."
    make test-app
    echo
    
    echo "✅ 所有功能模块测试完成！"
fi

echo
echo "==============================================="
echo "🎉 SSH手动测试演示完成！"
echo "==============================================="
echo
echo "📚 下次测试时，你可以："
echo "1. 参考 SSH_MANUAL_TESTING_GUIDE.md 详细教程"
echo "2. 查阅 SSH_QUICK_REFERENCE.md 快速参考"
echo "3. 推荐使用阶段3版本进行深入测试"
echo

cleanup
echo "🧹 已清理所有测试进程"
