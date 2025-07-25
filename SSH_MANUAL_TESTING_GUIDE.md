# SSH通信项目 - 手动测试教程

## 🎯 概述

本教程将指导你如何手动测试SSH通信项目的8个阶段，每个阶段都有对应的服务器和客户端程序。通过手动测试，你可以更好地理解每个阶段的功能和SSH协议的演进过程。

## 📋 准备工作

### 1. 编译所有版本
```bash
# 编译所有SSH版本
make all

# 检查编译结果
ls -la build/
```

你应该看到以下可执行文件：
- `ssh_server` - 阶段1基础服务器
- `ssh_client` - 阶段1基础客户端
- `ssh_server_v2` - 阶段2协议协商服务器
- `ssh_client_v2` - 阶段2协议协商客户端
- `ssh_server_v3` - 阶段3完整SSH服务器
- `ssh_client_v3` - 阶段3完整SSH客户端
- `ssh_server_v4` - 阶段4加密优化服务器
- `ssh_client_v4` - 阶段4加密优化客户端

### 2. 准备测试环境
```bash
# 确保端口2222未被占用
sudo netstat -tlnp | grep :2222

# 如果有进程占用，停止它
sudo pkill -f ssh_server
```

---

## 🏗️ 阶段一：基础网络通信测试

### 功能说明
- 纯TCP套接字通信
- 简单的文本消息传输
- 多客户端支持

### 测试步骤

#### 步骤1：启动基础服务器
```bash
# 终端1 - 启动服务器
./build/ssh_server
```

你应该看到类似输出：
```
[2025-07-25 xx:xx:xx] [INFO] Starting SSH Server on port 2222
[2025-07-25 xx:xx:xx] [INFO] Server socket created and listening on port 2222
[2025-07-25 xx:xx:xx] [INFO] SSH Server started on port 2222
[2025-07-25 xx:xx:xx] [INFO] Waiting for connections...
```

#### 步骤2：使用客户端连接
```bash
# 终端2 - 启动客户端
./build/ssh_client
```

#### 步骤3：测试通信
在客户端终端中输入：
```
Hello Server
How are you?
quit
```

#### 步骤4：观察结果
**服务器端**应显示：
```
[INFO] New client connected from 127.0.0.1:xxxxx (slot 0)
Welcome to Simple SSH Server!
[INFO] Received from client: Hello Server
Server received: Hello Server
[INFO] Received from client: How are you?
Server received: How are you?
[INFO] Client requested disconnect
```

**客户端**应显示：
```
Connected to server 127.0.0.1:2222
Welcome to Simple SSH Server!
> Hello Server
Server: Server received: Hello Server
> How are you?
Server: Server received: How are you?
> quit
Disconnected from server
```

#### 步骤5：测试多客户端（可选）
```bash
# 在多个终端中同时运行客户端
./build/ssh_client
```

---

## 🤝 阶段二：协议版本协商测试

### 功能说明
- SSH版本字符串交换
- 协议兼容性检查
- 标准SSH握手流程

### 测试步骤

#### 步骤1：启动SSH服务器v2
```bash
# 终端1
./build/ssh_server_v2
```

预期输出：
```
[INFO] Starting SSH Server on port 2222
[INFO] SSH Protocol Version: SSH-2.0-MySSH_1.0
[INFO] Waiting for SSH connections...
```

#### 步骤2：使用SSH客户端v2连接
```bash
# 终端2
./build/ssh_client_v2
```

#### 步骤3：观察版本协商过程
**服务器端**应显示：
```
[INFO] New SSH client connected from 127.0.0.1:xxxxx
[INFO] Sending SSH version: SSH-2.0-MySSH_1.0 server
[INFO] Received SSH version line: SSH-2.0-MySSH_1.0 client
[INFO] SSH version compatibility check passed
[INFO] SSH version exchange completed successfully
```

**客户端**应显示：
```
[INFO] Starting SSH version exchange...
[INFO] Sending SSH version: SSH-2.0-MySSH_1.0 client
[INFO] Received SSH version line: SSH-2.0-MySSH_1.0 server
[INFO] SSH version exchange completed successfully
Connected to SSH server. Type messages (quit/exit to disconnect):
```

#### 步骤4：测试消息传输
```
Test message from SSH client
quit
```

#### 步骤5：使用telnet观察版本交换
```bash
# 终端3 - 使用telnet观察协议
telnet 127.0.0.1 2222
```

输入：
```
SSH-2.0-TestClient_1.0 test
Hello SSH Server
quit
```

你应该立即看到服务器回复：`SSH-2.0-MySSH_1.0 server`

---

## 🔐 阶段三：密钥交换和完整SSH测试

### 功能说明
- Diffie-Hellman密钥交换
- AES加密通信
- 用户认证
- SSH通道管理
- 应用层通信

### 测试步骤

#### 步骤1：启动SSH服务器v3
```bash
# 终端1
./build/ssh_server_v3
```

#### 步骤2：使用SSH客户端v3连接
```bash
# 终端2
./build/ssh_client_v3
```

#### 步骤3：观察完整SSH握手过程
你应该看到：
1. **版本协商**
2. **密钥交换初始化**
3. **Diffie-Hellman密钥交换**
4. **用户认证**
5. **通道建立**

#### 步骤4：测试应用层功能
连接成功后，尝试：
```
ls
pwd
echo "Hello SSH World"
exit
```

---

## 🚀 阶段四：加密优化版本测试

### 功能说明
- 优化的AES加密实现
- 增强的安全性

### 测试步骤

#### 步骤1：启动SSH服务器v4
```bash
# 终端1
./build/ssh_server_v4
```

#### 步骤2：使用SSH客户端v4连接
```bash
# 终端2
./build/ssh_client_v4
```

**注意**：如果v4版本连接失败，这是已知问题，请使用v3版本。

---

## 🧪 阶段五至八：功能模块独立测试

这些阶段的功能已集成到v3版本中，但也提供了独立的测试程序。

### 阶段五：SSH消息格式测试
```bash
make test-packet
```

观察输出，确认：
- SSH数据包创建成功
- 数据包序列化和解析正确
- 消息类型识别正确

### 阶段六：用户认证测试
```bash
make test-auth
```

观察输出，确认：
- 用户数据库创建
- 认证请求处理
- 认证成功/失败消息

### 阶段七：安全通道管理测试
```bash
make test-channel
```

观察输出，确认：
- 通道创建和管理
- 通道数据传输
- 通道关闭

### 阶段八：应用层通信测试
```bash
make test-app
```

观察输出，确认：
- 命令执行功能
- 标准输入输出处理
- 进程管理

---

## 🔧 高级测试技巧

### 1. 使用netcat监控通信
```bash
# 监听端口，观察原始数据
nc -l 2223 | hexdump -C

# 在另一个终端
echo "SSH-2.0-TestClient" | nc 127.0.0.1 2222
```

### 2. 使用tcpdump抓包分析
```bash
# 抓取本地回环接口的数据包
sudo tcpdump -i lo -A port 2222
```

### 3. 压力测试
```bash
# 同时启动多个客户端测试并发性能
for i in {1..10}; do
    (echo "Client $i test" | ./build/ssh_client) &
done
wait
```

### 4. 日志分析
```bash
# 实时查看服务器日志
tail -f /var/log/ssh_server.log  # 如果有日志文件

# 或者重定向输出到文件
./build/ssh_server_v3 > server.log 2>&1 &
tail -f server.log
```

---

## 📊 测试结果验证

### 成功标准

#### 阶段一：基础通信
- ✅ 服务器成功监听端口2222
- ✅ 客户端能够连接并发送消息
- ✅ 服务器能接收并回显消息
- ✅ 支持多客户端并发连接

#### 阶段二：版本协商
- ✅ 服务器发送正确的SSH版本字符串
- ✅ 客户端发送正确的SSH版本字符串
- ✅ 双方完成版本兼容性检查
- ✅ 建立SSH连接状态

#### 阶段三：完整SSH
- ✅ 完成版本协商
- ✅ 执行密钥交换（可能有警告，但不影响后续功能）
- ✅ 用户认证成功
- ✅ 建立安全通道
- ✅ 支持基本命令执行

#### 阶段四：加密优化
- ⚠️ 可能存在连接问题（已知bug）
- 建议使用阶段三版本

#### 阶段五至八：功能模块
- ✅ 各个测试程序运行无错误
- ✅ 所有测试用例通过
- ✅ 功能正确集成到v3版本中

---

## 🐛 常见问题排除

### 1. 端口占用问题
```bash
# 查找占用端口的进程
sudo lsof -i :2222

# 强制终止进程
sudo pkill -f ssh_server
```

### 2. 编译错误
```bash
# 清理并重新编译
make clean
make all
```

### 3. 客户端连接超时
```bash
# 检查服务器是否运行
ps aux | grep ssh_server

# 检查防火墙设置
sudo iptables -L | grep 2222
```

### 4. 权限问题
```bash
# 确保可执行文件有执行权限
chmod +x build/ssh_*
```

---

## 🎓 学习建议

1. **按顺序测试**：从阶段一开始，逐步理解SSH协议的演进
2. **仔细观察日志**：每个阶段的日志输出包含重要的协议信息
3. **对比不同版本**：注意不同阶段版本的功能差异
4. **实验网络工具**：使用telnet、nc等工具加深理解
5. **阅读源码**：结合测试结果阅读相应的源代码实现

通过这个手动测试教程，你将获得对SSH协议完整而深入的理解！
