# SSH Communication Project Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE -g
LDFLAGS = 

# 目录结构
SRC_DIR = src
COMMON_DIR = $(SRC_DIR)/common
NETWORK_DIR = $(SRC_DIR)/network
BUILD_DIR = build

# 源文件
COMMON_SOURCES = $(COMMON_DIR)/logger.c
NETWORK_SOURCES = $(NETWORK_DIR)/socket_utils.c
SERVER_SOURCES = $(NETWORK_DIR)/server.c
CLIENT_SOURCES = $(NETWORK_DIR)/client.c

# 目标文件
SERVER_TARGET = ssh_server
CLIENT_TARGET = ssh_client

# 默认目标
all: $(BUILD_DIR) $(SERVER_TARGET) $(CLIENT_TARGET)

# 创建构建目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 编译服务器
$(SERVER_TARGET): $(SERVER_SOURCES) $(NETWORK_SOURCES) $(COMMON_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDFLAGS)
	@echo "Server built successfully: $(BUILD_DIR)/$(SERVER_TARGET)"

# 编译客户端
$(CLIENT_TARGET): $(CLIENT_SOURCES) $(NETWORK_SOURCES) $(COMMON_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDFLAGS)
	@echo "Client built successfully: $(BUILD_DIR)/$(CLIENT_TARGET)"

# 清理构建文件
clean:
	rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned"

# 运行服务器
run-server: $(SERVER_TARGET)
	@echo "Starting SSH server on port 2222..."
	./$(BUILD_DIR)/$(SERVER_TARGET)

# 运行客户端
run-client: $(CLIENT_TARGET)
	@echo "Starting SSH client..."
	./$(BUILD_DIR)/$(CLIENT_TARGET)

# 测试连接（在两个终端中运行）
test: all
	@echo "Build completed. Run the following commands in separate terminals:"
	@echo "Terminal 1: make run-server"
	@echo "Terminal 2: make run-client"

# 调试版本
debug: CFLAGS += -DDEBUG -O0
debug: all

# 安装依赖（Ubuntu/Debian）
install-deps:
	sudo apt-get update
	sudo apt-get install -y build-essential

# 显示帮助
help:
	@echo "Available targets:"
	@echo "  all         - Build both server and client"
	@echo "  clean       - Remove build directory"
	@echo "  run-server  - Run the SSH server"
	@echo "  run-client  - Run the SSH client"
	@echo "  test        - Build and show test instructions"
	@echo "  debug       - Build with debug flags"
	@echo "  install-deps- Install build dependencies"
	@echo "  help        - Show this help message"

.PHONY: all clean run-server run-client test debug install-deps help
