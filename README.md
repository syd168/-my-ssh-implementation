# SSH通信项目 - 阶段一：基础网络通信

## 项目概述

这是SSH通信学习项目的第一阶段实现，提供了基础的TCP客户端-服务器通信功能。这个阶段的目标是建立稳定的网络连接基础，为后续的SSH协议实现做准备。

## 功能特性

### 服务器端 (`ssh_server`)
- 多客户端并发连接支持（最多10个连接）
- 非阻塞I/O处理
- 简单的回显服务
- 连接状态管理
- 详细的日志记录

### 客户端 (`ssh_client`)
- 连接到指定服务器
- 交互式消息发送
- 实时接收服务器响应
- 优雅的连接关闭

### 核心功能
- TCP socket创建和管理
- 非阻塞I/O处理
- 错误处理和恢复
- 日志系统
- 连接状态跟踪

## 编译和运行

### 编译项目
```bash
# 编译所有目标
make all

# 或者分别编译
make ssh_server
make ssh_client

# 调试版本
make debug
```

### 运行测试

#### 方法一：使用Makefile命令
```bash
# 终端1 - 启动服务器
make run-server

# 终端2 - 启动客户端
make run-client
```

#### 方法二：直接运行可执行文件
```bash
# 终端1 - 启动服务器（默认端口2222）
./build/ssh_server

# 或指定端口
./build/ssh_server 8080

# 终端2 - 启动客户端
./build/ssh_client

# 或连接到指定服务器和端口
./build/ssh_client 127.0.0.1 8080
```

## 使用示例

### 服务器输出示例
```
[2025-07-25 10:30:15] [INFO] Server socket created and listening on port 2222
[2025-07-25 10:30:15] [INFO] SSH Server started on port 2222
[2025-07-25 10:30:15] [INFO] Waiting for connections...
[2025-07-25 10:30:20] [INFO] New client connected from 127.0.0.1:45678 (slot 0)
[2025-07-25 10:30:25] [INFO] Received from client: Hello Server!
[2025-07-25 10:30:30] [INFO] Client requested disconnect
[2025-07-25 10:30:30] [INFO] Closing client connection (slot 0)
```

### 客户端交互示例
```
[2025-07-25 10:30:20] [INFO] Connected to server 127.0.0.1:2222
Server: Welcome to Simple SSH Server!
Connected to server. Type messages (quit/exit to disconnect):
> Hello Server!
Server: Server received: Hello Server!
> How are you?
Server: Server received: How are you?
> quit
[2025-07-25 10:30:30] [INFO] Disconnecting from server...
[2025-07-25 10:30:30] [INFO] Client disconnected
```

## 技术要点

### 1. 非阻塞I/O
- 服务器和客户端都使用非阻塞socket
- 使用select()进行多路复用
- 避免阻塞操作影响程序响应性

### 2. 错误处理
- 完善的错误码定义和处理
- 网络异常的优雅处理
- 连接丢失的自动检测

### 3. 内存管理
- 避免缓冲区溢出
- 安全的字符串操作
- 资源的及时释放

### 4. 日志系统
- 分级日志输出（DEBUG, INFO, WARN, ERROR）
- 时间戳记录
- 详细的操作跟踪

## 项目结构

```
SSH_communication/
├── src/
│   ├── common/
│   │   ├── common.h          # 通用定义和声明
│   │   └── logger.c          # 日志系统实现
│   └── network/
│       ├── socket_utils.h    # Socket工具函数声明
│       ├── socket_utils.c    # Socket工具函数实现
│       ├── server.c          # 服务器主程序
│       └── client.c          # 客户端主程序
├── build/                    # 编译输出目录
├── Makefile                  # 构建脚本
├── README.md                 # 本文件
└── solution.md               # 整体项目方案
```

## 测试建议

### 基本功能测试
1. **单客户端连接测试**
   - 启动服务器
   - 连接一个客户端
   - 发送消息并验证回显
   - 正常断开连接

2. **多客户端并发测试**
   - 同时连接多个客户端
   - 验证消息独立处理
   - 测试连接数限制

3. **异常情况测试**
   - 强制关闭客户端（Ctrl+C）
   - 强制关闭服务器
   - 网络中断模拟

### 压力测试
```bash
# 可以编写简单脚本测试并发连接
for i in {1..5}; do
    echo "Test message $i" | nc 127.0.0.1 2222 &
done
```

## 已知限制

1. **安全性**：目前是明文传输，没有加密
2. **协议**：使用简单的文本协议，不是标准SSH格式
3. **认证**：没有身份验证机制
4. **功能**：只支持简单的文本消息传输

## 下一步计划

阶段一完成后，我们将进入阶段二：协议版本协商，实现：
- SSH版本字符串交换
- 协议兼容性检查
- 规范的SSH消息格式

## 故障排除

### 常见问题

1. **编译错误**
   ```bash
   # 确保安装了构建工具
   make install-deps
   ```

2. **端口占用**
   ```bash
   # 检查端口使用情况
   netstat -tulpn | grep 2222
   
   # 使用不同端口
   ./build/ssh_server 8080
   ```

3. **权限问题**
   ```bash
   # 确保可执行权限
   chmod +x build/ssh_server build/ssh_client
   ```

4. **连接失败**
   - 检查防火墙设置
   - 确认服务器已启动
   - 验证IP地址和端口号

## 学习要点

通过这个阶段的实现，你应该掌握：

1. **Socket编程基础**
   - TCP socket的创建和管理
   - 客户端-服务器模型
   - 网络字节序处理

2. **I/O多路复用**
   - select()函数的使用
   - 非阻塞I/O的优势
   - 事件驱动编程模式

3. **错误处理机制**
   - 网络编程中的常见错误
   - 优雅的错误恢复
   - 日志记录的重要性

4. **系统编程技巧**
   - 信号处理
   - 进程间通信基础
   - 资源管理

继续下一阶段前，建议充分测试当前实现，确保网络通信基础牢固可靠。
