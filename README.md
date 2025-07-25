# SSH通信项目

[![Language](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](#)

## 项目概述

这是一个教育性的SSH协议实现项目，旨在深入理解SSH协议的工作原理。项目采用渐进式开发方式，逐步实现SSH协议的各个组件和功能，从最基础的TCP通信到完整的SSH协议栈。

本项目包含8个开发阶段，最终实现了具备完整功能的SSH协议栈，包括版本协商、密钥交换、加密通信、用户认证、通道管理和应用层通信等功能。

## 功能特性

- ✅ 基础TCP客户端/服务器通信
- ✅ SSH协议版本协商
- ✅ Diffie-Hellman密钥交换
- ✅ AES加密通信
- ✅ 用户认证机制
- ✅ 多通道管理
- ✅ 应用层通信（远程命令执行）

## 技术架构

项目采用模块化设计，按功能划分为以下核心模块：

- **common**: 日志记录和通用工具函数
- **crypto**: AES加密和Diffie-Hellman密钥交换实现
- **network**: 网络通信和socket工具
- **protocol**: SSH协议实现（版本协商、密钥交换、认证、通道管理等）
- **app**: 应用层通信实现

## 系统要求

- Linux操作系统（推荐Ubuntu/Debian）
- GCC编译器
- GNU Make
- build-essential包

## 安装和构建

```bash
# 克隆项目
git clone <repository-url>
cd SSH_communication

# 构建所有版本
make

# 或者构建特定版本
make ssh_server_v3 ssh_client_v3
```

## SSH版本说明

项目包含多个版本的SSH实现，每个版本对应不同的开发阶段：

### 阶段一：基础网络通信
- **ssh_server** / **ssh_client**: 基础TCP套接字通信实现
- 运行命令：
  ```bash
  ./build/ssh_server
  ./build/ssh_client
  ```

### 阶段二：协议版本协商
- **ssh_server_v2** / **ssh_client_v2**: 实现SSH版本协商
- 运行命令：
  ```bash
  ./build/ssh_server_v2
  ./build/ssh_client_v2
  ```

### 阶段三：密钥交换
- **ssh_server_v3** / **ssh_client_v3**: 实现Diffie-Hellman密钥交换和基本加密
- 运行命令：
  ```bash
  ./build/ssh_server_v3
  ./build/ssh_client_v3
  ```

### 阶段四：加密增强版
- **ssh_server_v4** / **ssh_client_v4**: 实现增强的加密功能
- 运行命令：
  ```bash
  ./build/ssh_server_v4
  ./build/ssh_client_v4
  ```

### 最终版本：完整SSH实现
- **ssh_server_final** / **ssh_client_final**: 实现完整的SSH功能，包括用户登录、文本通信和文件传输
- 运行命令：
  ```bash
  ./build/ssh_server_final
  ./build/ssh_client_final
  ```

## 使用说明

### 运行完整SSH协议栈 (推荐)

1. 启动SSH服务器：
   ```bash
   make run-ssh-server-v3
   ```

2. 在另一个终端启动SSH客户端：
   ```bash
   make run-ssh-client-v3
   ```

3. 输入用户名和密码进行认证（默认用户名: `testuser`，密码: `testpass`）

4. 执行命令或使用shell功能

### 测试各个模块

项目提供独立的测试程序来验证各个模块的功能：

```bash
make test-packet     # 测试SSH消息格式
make test-auth       # 测试用户认证
make test-channel    # 测试通道管理
make test-app        # 测试应用层通信
```

## 项目结构

```
SSH_communication/
├── src/
│   ├── common/          # 通用工具和日志系统
│   ├── crypto/          # 加密算法实现
│   ├── network/         # 网络通信实现
│   ├── protocol/        # SSH协议实现
│   └── app/             # 应用层通信实现
├── build/               # 编译输出目录
├── docs/                # 文档目录
├── tests/               # 测试脚本
├── Makefile             # 构建配置
└── README.md            # 项目说明文档
```

## 开发阶段

项目按以下8个阶段逐步实现：

1. **阶段1**: 基础网络通信 - 实现TCP客户端/服务器通信
2. **阶段2**: 协议版本协商 - 实现SSH协议版本交换
3. **阶段3**: 密钥交换实现 - 实现Diffie-Hellman密钥交换
4. **阶段4**: 加密算法实现 - 实现AES加密通信
5. **阶段5**: SSH消息格式 - 实现SSH数据包格式处理
6. **阶段6**: 用户认证实现 - 实现用户身份验证
7. **阶段7**: 安全通道建立 - 实现SSH通道管理
8. **阶段8**: 应用层通信 - 实现远程命令执行

## 测试

项目提供全面的测试脚本：

```bash
# 测试所有阶段
./test_all_stages.sh

# 测试特定阶段
./test_stage1.sh
./test_stage2.sh
./test_stage3.sh
# ... 等等
```

## 文档

项目包含详细的文档说明：

- [项目完整报告](PROJECT_COMPLETE_REPORT.md)
- [各阶段完成报告](STAGE1_COMPLETE.md) (STAGE1_COMPLETE.md 到 STAGE8_COMPLETE.md)
- [SSH快速参考](SSH_QUICK_REFERENCE.md)
- [手动测试指南](SSH_MANUAL_TESTING_GUIDE.md)

## 许可证

本项目采用MIT许可证，详情请见[LICENSE](LICENSE)文件。

## 免责声明

本项目仅供学习和研究目的，不应用于生产环境。实现的加密算法和协议可能不符合生产环境的安全要求。