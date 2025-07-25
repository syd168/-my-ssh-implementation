# SSH Communication Project Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE -g
LDFLAGS = 

# 目录
SRC_DIR = src
COMMON_DIR = $(SRC_DIR)/common
PROTOCOL_DIR = $(SRC_DIR)/protocol
CRYPTO_DIR = $(SRC_DIR)/crypto
NETWORK_DIR = $(SRC_DIR)/network
APP_DIR = $(SRC_DIR)/app
BUILD_DIR = build

# 源文件
COMMON_SOURCES = $(COMMON_DIR)/logger.c
PROTOCOL_SOURCES = $(PROTOCOL_DIR)/version.c $(PROTOCOL_DIR)/kex.c $(PROTOCOL_DIR)/ssh_encryption.c $(PROTOCOL_DIR)/ssh_packet.c $(PROTOCOL_DIR)/auth.c
PROTOCOL_SOURCES_V3 = $(PROTOCOL_SOURCES) $(PROTOCOL_DIR)/channel.c
PROTOCOL_SOURCES_V4 = $(PROTOCOL_SOURCES)
APP_SOURCES = $(APP_DIR)/ssh_app.c
CRYPTO_SOURCES = $(CRYPTO_DIR)/dh.c $(CRYPTO_DIR)/aes.c
NETWORK_SOURCES = $(NETWORK_DIR)/socket_utils.c
SSH_SERVER_SOURCES = $(NETWORK_DIR)/ssh_server.c
SSH_CLIENT_SOURCES = $(NETWORK_DIR)/ssh_client.c
# 保留原始的简单版本
SERVER_SOURCES = $(NETWORK_DIR)/server.c
CLIENT_SOURCES = $(NETWORK_DIR)/client.c

# 目标文件
SSH_SERVER_V4_TARGET = ssh_server_v4
SSH_CLIENT_V4_TARGET = ssh_client_v4
SSH_SERVER_V3_TARGET = ssh_server_v3
SSH_CLIENT_V3_TARGET = ssh_client_v3
SSH_SERVER_TARGET = ssh_server_v2
SSH_CLIENT_TARGET = ssh_client_v2
SERVER_TARGET = ssh_server
CLIENT_TARGET = ssh_client
AES_TEST_TARGET = test_aes
PACKET_TEST_TARGET = test_packet
AUTH_TEST_TARGET = test_auth
CHANNEL_TEST_TARGET = test_channel
APP_TEST_TARGET = test_app

# 默认目标 - 编译所有SSH版本
all: $(BUILD_DIR) $(SERVER_TARGET) $(CLIENT_TARGET) $(SSH_SERVER_TARGET) $(SSH_CLIENT_TARGET) $(SSH_SERVER_V3_TARGET) $(SSH_CLIENT_V3_TARGET) $(SSH_SERVER_V4_TARGET) $(SSH_CLIENT_V4_TARGET)

# 编译所有版本（与all相同，保持兼容性）
all-versions: all

# 创建构建目录
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# 编译SSH服务器（阶段二版本）
$(SSH_SERVER_TARGET): $(SSH_SERVER_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES) $(CRYPTO_SOURCES) $(COMMON_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDFLAGS)
	@echo "SSH Server v2 built successfully: $(BUILD_DIR)/$(SSH_SERVER_TARGET)"

# 编译SSH客户端（阶段二版本）
$(SSH_CLIENT_TARGET): $(SSH_CLIENT_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES) $(CRYPTO_SOURCES) $(COMMON_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDFLAGS)
	@echo "SSH Client v2 built successfully: $(BUILD_DIR)/$(SSH_CLIENT_TARGET)"

# 编译原始服务器（阶段一版本）
$(SERVER_TARGET): $(SERVER_SOURCES) $(NETWORK_SOURCES) $(COMMON_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDFLAGS)
	@echo "Server built successfully: $(BUILD_DIR)/$(SERVER_TARGET)"

# 编译原始客户端（阶段一版本）
$(CLIENT_TARGET): $(CLIENT_SOURCES) $(NETWORK_SOURCES) $(COMMON_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDFLAGS)
	@echo "Client built successfully: $(BUILD_DIR)/$(CLIENT_TARGET)"

# 编译AES测试程序
$(AES_TEST_TARGET): $(BUILD_DIR) $(CRYPTO_DIR)/test_aes.c $(CRYPTO_SOURCES) $(COMMON_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(CRYPTO_DIR)/test_aes.c $(CRYPTO_SOURCES) $(COMMON_SOURCES) $(LDFLAGS)
	@echo "AES test program built successfully: $(BUILD_DIR)/$@"

# 编译SSH消息格式测试程序
$(PACKET_TEST_TARGET): $(BUILD_DIR) $(PROTOCOL_DIR)/test_packet.c $(PROTOCOL_SOURCES) $(CRYPTO_SOURCES) $(COMMON_SOURCES) $(NETWORK_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(PROTOCOL_DIR)/test_packet.c $(PROTOCOL_SOURCES) $(CRYPTO_SOURCES) $(COMMON_SOURCES) $(NETWORK_SOURCES) $(LDFLAGS)
	@echo "SSH packet test program built successfully: $(BUILD_DIR)/$@"

# 编译用户认证测试程序
$(AUTH_TEST_TARGET): $(BUILD_DIR) $(PROTOCOL_DIR)/test_auth.c $(PROTOCOL_SOURCES) $(CRYPTO_SOURCES) $(COMMON_SOURCES) $(NETWORK_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(PROTOCOL_DIR)/test_auth.c $(PROTOCOL_SOURCES) $(CRYPTO_SOURCES) $(COMMON_SOURCES) $(NETWORK_SOURCES) $(LDFLAGS)
	@echo "SSH authentication test program built successfully: $(BUILD_DIR)/$@"

# 编译通道管理测试程序
$(CHANNEL_TEST_TARGET): $(BUILD_DIR) $(PROTOCOL_DIR)/test_channel.c $(PROTOCOL_SOURCES_V3) $(CRYPTO_SOURCES) $(COMMON_SOURCES) $(NETWORK_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(PROTOCOL_DIR)/test_channel.c $(PROTOCOL_SOURCES_V3) $(CRYPTO_SOURCES) $(COMMON_SOURCES) $(NETWORK_SOURCES) $(LDFLAGS)
	@echo "SSH channel management test program built successfully: $(BUILD_DIR)/$@"

# 编译应用层通信测试程序
$(APP_TEST_TARGET): $(BUILD_DIR) $(APP_DIR)/test_app.c $(APP_SOURCES) $(PROTOCOL_SOURCES_V3) $(CRYPTO_SOURCES) $(COMMON_SOURCES) $(NETWORK_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(APP_DIR)/test_app.c $(APP_SOURCES) $(PROTOCOL_SOURCES_V3) $(CRYPTO_SOURCES) $(COMMON_SOURCES) $(NETWORK_SOURCES) $(LDFLAGS)
	@echo "SSH application layer test program built successfully: $(BUILD_DIR)/$@"

# 清理构建文件
clean:
	rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned"

# 运行SSH服务器v2
run-ssh-server: $(SSH_SERVER_TARGET)
	@echo "Starting SSH server v2 on port 2222..."
	./$(BUILD_DIR)/$(SSH_SERVER_TARGET)

# 运行SSH客户端v2
run-ssh-client: $(SSH_CLIENT_TARGET)
	@echo "Starting SSH client v2..."
	./$(BUILD_DIR)/$(SSH_CLIENT_TARGET)

# 运行原始服务器
run-server: $(SERVER_TARGET)
	@echo "Starting SSH server v1 on port 2222..."
	./$(BUILD_DIR)/$(SERVER_TARGET)

# 运行原始客户端
run-client: $(CLIENT_TARGET)
	@echo "Starting SSH client v1..."
	./$(BUILD_DIR)/$(CLIENT_TARGET)

# 测试SSH版本（在两个终端中运行）
test-ssh: all
	@echo "Build completed. Run the following commands in separate terminals:"
	@echo "Terminal 1: make run-ssh-server"
	@echo "Terminal 2: make run-ssh-client"

# 测试连接（在两个终端中运行）
test: all-versions
	@echo "All versions built. Available tests:"
	@echo "SSH v2: make run-ssh-server & make run-ssh-client"
	@echo "SSH v1: make run-server & make run-client"

# 调试版本
debug: CFLAGS += -DDEBUG -O0
debug: all

# 安装依赖（Ubuntu/Debian）
install-deps:
	sudo apt-get update
	sudo apt-get install -y build-essential

# 显示帮助
	@echo "SSH communication development complete!"

# SSH服务器v3 (支持密钥交换)
$(SSH_SERVER_V3_TARGET): $(BUILD_DIR) $(NETWORK_DIR)/ssh_server_v3.c $(COMMON_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES_V3) $(APP_SOURCES) $(CRYPTO_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(NETWORK_DIR)/ssh_server_v3.c $(COMMON_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES_V3) $(APP_SOURCES) $(CRYPTO_SOURCES) $(LDFLAGS)
	@echo "SSH Server v3 built successfully: $(BUILD_DIR)/$@"

# SSH客户端v3 (支持密钥交换)
$(SSH_CLIENT_V3_TARGET): $(BUILD_DIR) $(NETWORK_DIR)/ssh_client_v3.c $(COMMON_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES_V3) $(APP_SOURCES) $(CRYPTO_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(NETWORK_DIR)/ssh_client_v3.c $(COMMON_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES_V3) $(APP_SOURCES) $(CRYPTO_SOURCES) $(LDFLAGS)
	@echo "SSH Client v3 built successfully: $(BUILD_DIR)/$@"

# 运行SSH服务器v3
run-ssh-server-v3: $(SSH_SERVER_V3_TARGET)
	@echo "Starting SSH Server v3 (with key exchange) on port 2222..."
	./$(BUILD_DIR)/$(SSH_SERVER_V3_TARGET)

# 运行SSH客户端v3
run-ssh-client-v3: $(SSH_CLIENT_V3_TARGET)
	@echo "Starting SSH Client v3 (with key exchange)..."
	./$(BUILD_DIR)/$(SSH_CLIENT_V3_TARGET)

# SSH服务器v4 (支持加密)
$(SSH_SERVER_V4_TARGET): $(BUILD_DIR) $(NETWORK_DIR)/ssh_server_v4.c $(COMMON_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES_V4) $(CRYPTO_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(NETWORK_DIR)/ssh_server_v4.c $(COMMON_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES_V4) $(CRYPTO_SOURCES) $(LDFLAGS)
	@echo "SSH Server v4 built successfully: $(BUILD_DIR)/$@"

# SSH客户端v4 (支持加密)
$(SSH_CLIENT_V4_TARGET): $(BUILD_DIR) $(NETWORK_DIR)/ssh_client_v4.c $(COMMON_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES_V4) $(CRYPTO_SOURCES)
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(NETWORK_DIR)/ssh_client_v4.c $(COMMON_SOURCES) $(NETWORK_SOURCES) $(PROTOCOL_SOURCES_V4) $(CRYPTO_SOURCES) $(LDFLAGS)
	@echo "SSH Client v4 built successfully: $(BUILD_DIR)/$@"

# 运行SSH服务器v4
run-ssh-server-v4: $(SSH_SERVER_V4_TARGET)
	@echo "Starting SSH server v4..."
	./$(BUILD_DIR)/$(SSH_SERVER_V4_TARGET)

# 运行SSH客户端v4
run-ssh-client-v4: $(SSH_CLIENT_V4_TARGET)
	@echo "Starting SSH client v4..."
	./$(BUILD_DIR)/$(SSH_CLIENT_V4_TARGET)

help:
	@echo "Available targets:"
	@echo "  all            - Build all SSH versions (阶段1-4: ssh_server, ssh_client, ssh_server_v2, ssh_client_v2, ssh_server_v3, ssh_client_v3, ssh_server_v4, ssh_client_v4)"
	@echo "  all-versions   - Same as 'all' (build all versions)"
	@echo "  clean          - Remove build directory"
	@echo ""
	@echo "Individual stage builds:"
	@echo "  ssh_server     - 阶段1: Basic server (ssh_server)"
	@echo "  ssh_client     - 阶段1: Basic client (ssh_client)"
	@echo "  ssh_server_v2  - 阶段2: SSH server with protocol negotiation"
	@echo "  ssh_client_v2  - 阶段2: SSH client with protocol negotiation"
	@echo "  ssh_server_v3  - 阶段3: SSH server with key exchange"
	@echo "  ssh_client_v3  - 阶段3: SSH client with key exchange"
	@echo "  ssh_server_v4  - 阶段4: SSH server with encryption"
	@echo "  ssh_client_v4  - 阶段4: SSH client with encryption"
	@echo ""
	@echo "Run targets:"
	@echo "  run-server     - Run simple server v1 (阶段1)"
	@echo "  run-client     - Run simple client v1 (阶段1)"
	@echo "  run-ssh-server - Run SSH server v2 (阶段2)"
	@echo "  run-ssh-client - Run SSH client v2 (阶段2)"
	@echo "  run-ssh-server-v3 - Run SSH server v3 (阶段3)"
	@echo "  run-ssh-client-v3 - Run SSH client v3 (阶段3)"
	@echo "  run-ssh-server-v4 - Run SSH server v4 (阶段4)"
	@echo "  run-ssh-client-v4 - Run SSH client v4 (阶段4)"
	@echo ""
	@echo "Test targets:"
	@echo "  test-ssh       - Build SSH v2 and show test instructions"
	@echo "  test           - Build all versions and show test options"
	@echo "  test-aes       - Build and run AES encryption test"
	@echo "  test-packet    - Build and run SSH packet format test"
	@echo "  test-auth      - Build and run SSH authentication test"
	@echo "  test-channel   - Build and run SSH channel management test"
	@echo "  test-stage4    - Run stage 4 encryption tests"
	@echo "  test-stage5    - Run stage 5 packet format tests"
	@echo "  test-stage6    - Run stage 6 authentication tests"
	@echo "  test-stage7    - Run stage 7 channel management tests"
	@echo "  demo-ssh       - Show demo of different SSH versions"
	@echo "  debug          - Build with debug flags"
	@echo "  install-deps   - Install build dependencies"
	@echo "  help           - Show this help message"

# AES测试
test-aes: $(AES_TEST_TARGET)
	@echo "Running AES encryption test..."
	./$(BUILD_DIR)/$(AES_TEST_TARGET)

# SSH消息格式测试
test-packet: $(PACKET_TEST_TARGET)
	@echo "Running SSH packet format test..."
	./$(BUILD_DIR)/$(PACKET_TEST_TARGET)

# SSH用户认证测试
test-auth: $(AUTH_TEST_TARGET)
	@echo "Running SSH authentication test..."
	./$(BUILD_DIR)/$(AUTH_TEST_TARGET)

# SSH通道管理测试
test-channel: $(CHANNEL_TEST_TARGET)
	@echo "Running SSH channel management test..."
	./$(BUILD_DIR)/$(CHANNEL_TEST_TARGET)

# 阶段四测试
test-stage4:
	@echo "Running Stage 4 encryption tests..."
	chmod +x test_stage4.sh
	./test_stage4.sh

# 阶段四v4测试
test-stage4-v4:
	@echo "Running Stage 4 v4 encryption tests..."
	chmod +x test_stage4_v4.sh
	./test_stage4_v4.sh

# 阶段五测试
test-stage5:
	@echo "Running Stage 5 packet format tests..."
	$(MAKE) test-packet

# 阶段六测试
test-stage6:
	@echo "Running Stage 6 authentication tests..."
	$(MAKE) test-auth

# 阶段七测试
test-stage7:
	@echo "Running Stage 7 channel management tests..."
	$(MAKE) test-channel

# 应用层测试
test-app: $(APP_TEST_TARGET)
	@echo "Running SSH application layer test..."
	./$(BUILD_DIR)/$(APP_TEST_TARGET)

# 阶段八测试
test-stage8:
	@echo "Running Stage 8 application layer tests..."
	@chmod +x test_stage8.sh
	$(MAKE) test-app

# SSH版本演示
demo-ssh: $(BUILD_DIR)
	@chmod +x demo_ssh_versions.sh
	@echo "Running SSH versions demo..."
	./demo_ssh_versions.sh

.PHONY: all all-versions clean run-ssh-server run-ssh-client run-server run-client test-ssh test debug install-deps help test-aes test-stage4 test-packet test-stage5 test-auth test-stage6 test-channel test-stage7 demo-ssh
