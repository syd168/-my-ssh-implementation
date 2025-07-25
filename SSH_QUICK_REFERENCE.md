# SSH测试快速参考指南

## 🚀 快速开始

```bash
# 1. 编译所有版本
make all

# 2. 查看可用程序
ls build/

# 3. 基本测试流程：双终端操作
# 终端1：启动服务器
# 终端2：启动客户端
```

## 📋 各阶段测试命令

### 阶段1：基础通信
```bash
# 终端1 - 服务器
./build/ssh_server

# 终端2 - 客户端
./build/ssh_client
# 输入消息，输入quit退出
```

### 阶段2：版本协商
```bash
# 终端1 - 服务器
./build/ssh_server_v2

# 终端2 - 客户端
./build/ssh_client_v2
# 观察SSH版本交换过程
```

### 阶段3：完整SSH（推荐）
```bash
# 终端1 - 服务器
./build/ssh_server_v3

# 终端2 - 客户端
./build/ssh_client_v3
# 可以执行命令：ls, pwd, echo等
```

### 阶段4：加密优化（可能有问题）
```bash
# 终端1 - 服务器
./build/ssh_server_v4

# 终端2 - 客户端
./build/ssh_client_v4
```

### 阶段5-8：功能模块测试
```bash
make test-packet      # SSH消息格式
make test-auth        # 用户认证
make test-channel     # 通道管理
make test-app         # 应用层通信
```

## 🔧 实用测试命令

### 检查服务器状态
```bash
# 检查端口监听
netstat -tlnp | grep :2222

# 查看服务器进程
ps aux | grep ssh_server

# 停止所有服务器
pkill -f ssh_server
```

### 网络调试
```bash
# 使用telnet测试连接
telnet 127.0.0.1 2222

# 使用nc观察SSH握手
echo "SSH-2.0-TestClient" | nc 127.0.0.1 2222
```

### 日志和调试
```bash
# 重定向服务器日志到文件
./build/ssh_server_v3 > server.log 2>&1 &

# 实时查看日志
tail -f server.log

# 查看最近的日志
tail -20 server.log
```

## ⚡ 常用操作序列

### 完整测试序列（推荐v3版本）
```bash
# 1. 清理环境
pkill -f ssh_server
sleep 1

# 2. 启动v3服务器（后台）
./build/ssh_server_v3 &

# 3. 等待启动
sleep 2

# 4. 连接客户端
./build/ssh_client_v3

# 5. 在客户端中测试命令
# ls
# pwd
# echo "Hello SSH"
# exit
```

### 快速功能验证
```bash
# 验证所有功能模块
echo "Testing SSH modules..."
make test-packet && echo "✅ Packet module OK"
make test-auth && echo "✅ Auth module OK" 
make test-channel && echo "✅ Channel module OK"
make test-app && echo "✅ App module OK"
```

## 🎯 成功指标

### 阶段1成功标志
- 服务器显示 "Waiting for connections..."
- 客户端显示 "Connected to server"
- 消息正确传输和回显

### 阶段2成功标志
- 服务器显示 "SSH version exchange completed"
- 客户端显示 "Connected to SSH server"
- 版本字符串正确交换

### 阶段3成功标志
- 完成版本协商
- 显示认证成功信息
- 可以执行基本命令
- 命令有正确输出

## 🐛 故障排除

### 连接被拒绝
```bash
# 检查服务器是否运行
ps aux | grep ssh_server

# 重新启动服务器
pkill -f ssh_server && ./build/ssh_server_v3
```

### 端口占用
```bash
# 查找占用进程
sudo lsof -i :2222

# 强制终止
sudo pkill -f ":2222"
```

### 客户端卡住
```bash
# 使用Ctrl+C终止客户端
# 检查服务器日志
tail server.log
```

## 📱 移动测试技巧

### 一键重启测试
```bash
# 创建测试脚本
cat > quick_test.sh << 'EOF'
#!/bin/bash
pkill -f ssh_server
sleep 1
./build/ssh_server_v3 > server.log 2>&1 &
sleep 2
echo "Server started. Connect with: ./build/ssh_client_v3"
EOF

chmod +x quick_test.sh
./quick_test.sh
```

### 批量测试所有阶段
```bash
# 测试所有客户端/服务器版本
for version in "" "_v2" "_v3" "_v4"; do
    echo "Testing ssh_server$version and ssh_client$version"
    if [ -f "build/ssh_server$version" ]; then
        echo "✅ Found ssh_server$version"
    else
        echo "❌ Missing ssh_server$version"
    fi
done
```

---

💡 **提示**: 推荐使用阶段3版本（ssh_server_v3/ssh_client_v3）进行日常测试，它包含了最完整和稳定的SSH功能实现。
