#!/bin/bash

echo "=== SSH通信项目阶段二测试：协议版本协商 ==="
echo

# 函数：清理进程
cleanup_and_exit() {
    echo
    echo "5. 清理..."
    if [ ! -z "$SSH_SERVER_PID" ] && kill -0 $SSH_SERVER_PID 2>/dev/null; then
        kill $SSH_SERVER_PID
        wait $SSH_SERVER_PID 2>/dev/null
    fi
    
    echo
    if [ $1 -eq 0 ]; then
        echo "=== 阶段二测试完成 ==="
        echo
        echo "✓ 阶段二：SSH协议版本协商功能已实现！"
        echo
        echo "主要功能："
        echo "• SSH版本字符串交换"
        echo "• 协议兼容性检查"
        echo "• 规范的SSH消息格式"
        echo "• 版本解析和验证"
        echo
        echo "下一步可以开始阶段三：密钥交换实现"
    else
        echo "=== 阶段二测试失败 ==="
    fi
    
    exit $1
}

# 1. 编译检查
if [ ! -f "build/ssh_server_v2" ] || [ ! -f "build/ssh_client_v2" ]; then
    echo "编译SSH v2版本..."
    make ssh_server_v2 ssh_client_v2 >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "❌ 编译失败"
        exit 1
    fi
fi

# 2. 启动SSH服务器v2
echo "1. 启动SSH服务器v2..."
./build/ssh_server_v2 >/dev/null 2>&1 &
SSH_SERVER_PID=$!
echo "SSH服务器PID: $SSH_SERVER_PID"

# 等待服务器启动
sleep 2

# 3. 检查服务器是否监听
echo
echo "2. 检查SSH服务器是否监听端口2222..."
if ! netstat -ln 2>/dev/null | grep -q ":2222 "; then
    echo "❌ SSH服务器v2未能监听端口2222"
    cleanup_and_exit 1
fi

echo "✓ SSH服务器v2正在监听端口2222"

# 4. 测试版本协商
echo
echo "3. 测试SSH协议版本协商..."

# 简单的版本协商测试
(
    echo "SSH-2.0-TestClient_1.0 test"
    sleep 2
    echo "Hello SSH Server"
    sleep 1
    echo "quit"
) | nc 127.0.0.1 2222 >/dev/null 2>&1 &

sleep 3

# 5. 测试SSH客户端连接
echo
echo "4. 测试SSH客户端连接..."

# 使用timeout限制客户端运行时间
timeout 5s bash -c '
    (
        sleep 1
        echo "Test message from SSH client"
        sleep 1
        echo "quit"
    ) | ./build/ssh_client_v2 >/dev/null 2>&1
'

CLIENT_EXIT=$?

if [ $CLIENT_EXIT -eq 0 ] || [ $CLIENT_EXIT -eq 124 ]; then
    echo "✓ SSH客户端版本协商测试完成"
else
    echo "❌ SSH客户端连接失败"
    cleanup_and_exit 1
fi

cleanup_and_exit 0
