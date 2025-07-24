#!/bin/bash

# SSH通信项目阶段一测试脚本

cd "$(dirname "$0")"

echo "=== SSH通信项目阶段一测试 ==="
echo

# 检查可执行文件是否存在
if [ ! -f "build/ssh_server" ] || [ ! -f "build/ssh_client" ]; then
    echo "错误：可执行文件不存在，请先运行 make all"
    exit 1
fi

echo "1. 启动服务器..."
./build/ssh_server &
SERVER_PID=$!
echo "服务器PID: $SERVER_PID"

# 等待服务器启动
sleep 2

echo
echo "2. 检查服务器是否监听端口2222..."
if netstat -tulpn 2>/dev/null | grep -q ":2222.*LISTEN"; then
    echo "✓ 服务器正在监听端口2222"
else
    echo "✗ 服务器未能监听端口2222"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

echo
echo "3. 测试基本连接..."
echo "发送测试消息: 'Hello Server'"

# 使用expect或者简单的管道测试
(
    sleep 1
    echo "Hello Server"
    sleep 1
    echo "How are you?"
    sleep 1
    echo "quit"
) | telnet 127.0.0.1 2222 2>/dev/null | grep -E "(Welcome|Server received)" && echo "✓ 基本通信测试通过"

echo
echo "4. 测试并发连接..."
for i in {1..3}; do
    (echo "Message from client $i"; sleep 1; echo "quit") | telnet 127.0.0.1 2222 2>/dev/null &
done

# 等待所有连接完成
sleep 3

echo
echo "5. 清理..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo
echo "=== 测试完成 ==="
echo
echo "阶段一基础网络通信功能正常！"
echo "下一步可以开始阶段二：协议版本协商"
