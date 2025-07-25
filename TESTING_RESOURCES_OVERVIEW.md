# SSH手动测试资源总览

## 📁 已创建的测试资源

我为你创建了完整的SSH手动测试资源：

### 1. 📖 详细教程
**文件**: `SSH_MANUAL_TESTING_GUIDE.md`
- 🎯 完整的8个阶段手动测试教程
- 📋 每个阶段的详细测试步骤
- 🔧 高级测试技巧和网络调试方法
- 🐛 常见问题排除指南
- 🎓 学习建议和最佳实践

### 2. ⚡ 快速参考
**文件**: `SSH_QUICK_REFERENCE.md`
- 🚀 各阶段测试命令速查表
- 🔧 实用测试命令集合
- ⚡ 常用操作序列
- 🎯 成功指标检查表
- 📱 移动测试技巧

### 3. 🎬 交互式演示
**文件**: `demo_manual_testing.sh`
- 🎭 引导式测试演示脚本
- 📡 自动启动服务器演示
- 💻 客户端连接说明
- 📊 实时日志监控
- 🧪 功能模块批量测试

## 🚀 快速开始

### 方法一：使用交互式演示（推荐新手）
```bash
./demo_manual_testing.sh
```
这个脚本会引导你完成所有测试步骤。

### 方法二：直接手动测试（推荐有经验用户）

#### 测试最完整版本（阶段3）
```bash
# 终端1 - 启动服务器
./build/ssh_server_v3

# 终端2 - 启动客户端  
./build/ssh_client_v3

# 在客户端中尝试：
# ls
# pwd
# echo "Hello SSH"
# exit
```

#### 测试所有功能模块
```bash
make test-packet    # SSH消息格式
make test-auth      # 用户认证  
make test-channel   # 通道管理
make test-app       # 应用层通信
```

## 📋 测试清单

### ✅ 必测项目
- [ ] **阶段1** - 基础TCP通信：`ssh_server` + `ssh_client`
- [ ] **阶段2** - SSH版本协商：`ssh_server_v2` + `ssh_client_v2`  
- [ ] **阶段3** - 完整SSH协议：`ssh_server_v3` + `ssh_client_v3` ⭐
- [ ] **功能模块** - 独立测试：`make test-*`

### 🔍 可选测试
- [ ] **阶段4** - 加密优化：`ssh_server_v4` + `ssh_client_v4` (可能有问题)
- [ ] **网络调试** - 使用telnet/nc观察协议交换
- [ ] **并发测试** - 多客户端同时连接
- [ ] **压力测试** - 批量连接测试

## 🎯 重点推荐

### 🏆 最佳测试版本
**ssh_server_v3 + ssh_client_v3**
- ✅ 功能最完整
- ✅ 最稳定可靠
- ✅ 包含所有8个阶段的核心功能
- ✅ 适合深入学习SSH协议

### 📚 学习路径建议
1. **从简单开始** - 阶段1基础通信
2. **理解协议** - 阶段2版本协商  
3. **深入学习** - 阶段3完整SSH
4. **模块理解** - 功能模块独立测试
5. **实战应用** - 使用网络工具调试分析

## 💡 测试技巧

### 🔧 环境准备
```bash
# 确保编译完成
make all

# 清理旧进程
pkill -f ssh_server

# 检查端口状态
netstat -tlnp | grep :2222
```

### 📊 监控日志
```bash
# 后台启动服务器并记录日志
./build/ssh_server_v3 > server.log 2>&1 &

# 实时查看日志
tail -f server.log
```

### 🔍 调试连接
```bash
# 使用telnet测试基本连接
telnet 127.0.0.1 2222

# 使用nc观察SSH握手
echo "SSH-2.0-TestClient" | nc 127.0.0.1 2222
```

## 🆘 遇到问题？

### 📖 查阅资源
1. 详细教程：`SSH_MANUAL_TESTING_GUIDE.md`
2. 快速参考：`SSH_QUICK_REFERENCE.md`  
3. 运行演示：`./demo_manual_testing.sh`

### 🐛 常见问题
- **连接被拒绝** → 检查服务器是否启动
- **端口占用** → 使用 `pkill -f ssh_server` 清理
- **客户端卡住** → 按Ctrl+C终止，检查服务器日志
- **权限错误** → 使用 `chmod +x build/ssh_*` 添加执行权限

---

🎉 **祝你测试愉快！通过手动测试，你将深入理解SSH协议的工作原理和实现细节。**
