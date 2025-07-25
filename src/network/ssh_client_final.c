#include "../common/common.h"
#include "../network/socket_utils.h"
#include "../protocol/ssh_protocol.h"
#include "../protocol/kex.h"
#include "../protocol/auth.h"
#include "../crypto/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>

#define SSH_PORT 2222
#define SERVER_IP "127.0.0.1"

// SSH客户端上下文
typedef struct {
    int socket_fd;
    ssh_version_info_t local_version;
    ssh_version_info_t server_version;
    ssh_protocol_state_t state;
    ssh_kex_context_t kex_ctx;
    ssh_auth_context_t auth_ctx;
    ssh_encryption_context_t encryption_ctx;
    int connected;
    int encryption_enabled;
} ssh_client_context_final_t;

static int running = 1;

// 信号处理函数
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_message(LOG_INFO, "Received shutdown signal");
        running = 0;
    }
}

// 初始化SSH客户端上下文
ssh_result_t init_ssh_client_context(ssh_client_context_final_t *ctx) {
    memset(ctx, 0, sizeof(ssh_client_context_final_t));
    ctx->socket_fd = -1;
    ctx->state = SSH_STATE_VERSION_EXCHANGE;
    ctx->encryption_enabled = 0;
    ctx->connected = 0;
    
    // 初始化客户端版本信息
    ssh_result_t result = ssh_init_version_info(&ctx->local_version, 0); // 0 = client
    if (result != SSH_OK) {
        return result;
    }
    
    // 初始化KEX上下文
    result = kex_init(&ctx->kex_ctx, 0); // 0 = client
    if (result != SSH_OK) {
        return result;
    }
    
    
    // 初始化认证上下文
    result = auth_init(&ctx->auth_ctx);
    if (result != SSH_OK) {
        return result;
    }
    
    return SSH_OK;
}

// 发送加密数据
ssh_result_t send_encrypted_data(ssh_client_context_final_t *ctx, const char *data, size_t len) {
    if (ctx->encryption_enabled) {
        // 加密数据
        unsigned char encrypted_data[MAX_BUFFER_SIZE];
        int encrypted_len;
        aes_context_t aes_ctx;
        aes_result_t aes_result;
        
        // 初始化AES加密上下文
        aes_result = aes_init(&aes_ctx, 
                              ctx->encryption_ctx.encryption_key, 
                              ctx->encryption_ctx.key_len, 
                              ctx->encryption_ctx.encryption_iv);
        if (aes_result != AES_SUCCESS) {
            log_message(LOG_ERROR, "Failed to initialize AES encryption context");
            return SSH_ERROR_CRYPTO;
        }
        
        // 加密数据
        aes_result = aes_encrypt_cbc(&aes_ctx, (const unsigned char*)data, len, encrypted_data, &encrypted_len);
        if (aes_result != AES_SUCCESS) {
            log_message(LOG_ERROR, "Failed to encrypt data");
            return SSH_ERROR_CRYPTO;
        }
        
        // 发送加密数据
        return send_data(ctx->socket_fd, (char*)encrypted_data, encrypted_len);
    } else {
        // 发送明文数据
        return send_data(ctx->socket_fd, data, len);
    }
}

// 接收并解密数据
ssh_result_t receive_and_decrypt_data(ssh_client_context_final_t *ctx, char *buffer, size_t buffer_len, size_t *received) {
    ssh_result_t result = receive_data(ctx->socket_fd, buffer, buffer_len, received);
    if (result != SSH_OK) {
        return result;
    }
    
    if (ctx->encryption_enabled && *received > 0) {
        // 解密数据
        unsigned char decrypted_data[MAX_BUFFER_SIZE];
        int decrypted_len;
        aes_context_t aes_ctx;
        aes_result_t aes_result;
        
        // 初始化AES解密上下文
        aes_result = aes_init(&aes_ctx, 
                              ctx->encryption_ctx.decryption_key, 
                              ctx->encryption_ctx.key_len, 
                              ctx->encryption_ctx.decryption_iv);
        if (aes_result != AES_SUCCESS) {
            log_message(LOG_ERROR, "Failed to initialize AES decryption context");
            return SSH_ERROR_CRYPTO;
        }
        
        // 解密数据
        aes_result = aes_decrypt_cbc(&aes_ctx, (unsigned char*)buffer, *received, decrypted_data, &decrypted_len);
        if (aes_result != AES_SUCCESS) {
            log_message(LOG_ERROR, "Failed to decrypt data");
            return SSH_ERROR_CRYPTO;
        }
        
        // 检查缓冲区大小
        if ((size_t)decrypted_len > buffer_len) {
            log_message(LOG_ERROR, "Decrypted data too large for buffer");
            return SSH_ERROR_BUFFER_TOO_SMALL;
        }
        
        // 复制解密后的数据到缓冲区
        memcpy(buffer, decrypted_data, decrypted_len);
        *received = decrypted_len;
    }
    
    return SSH_OK;
}

// 处理SSH版本交换
ssh_result_t handle_version_exchange(ssh_client_context_final_t *ctx) {
    ssh_result_t result;
    
    // 发送版本字符串
    result = ssh_send_version_string(ctx->socket_fd, &ctx->local_version);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to send SSH version string");
        return result;
    }
    
    log_message(LOG_INFO, "Sent SSH version: %s", ctx->local_version.full_version);
    
    // 接收服务器版本字符串
    result = ssh_receive_version_string(ctx->socket_fd, &ctx->server_version);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to receive SSH version string");
        return result;
    }
    
    log_message(LOG_INFO, "Received SSH version: %s", ctx->server_version.full_version);
    
    // 检查版本兼容性
    if (ctx->server_version.major_version != 2) {
        log_message(LOG_ERROR, "Incompatible SSH protocol version: %d.%d", 
                   ctx->server_version.major_version, ctx->server_version.minor_version);
        return SSH_ERROR_PROTOCOL;
    }
    
    ctx->state = SSH_STATE_KEY_EXCHANGE;
    return SSH_OK;
}

// 启用连接加密
ssh_result_t enable_connection_encryption(ssh_client_context_final_t *ctx) {
    // 初始化加密上下文（简化实现，实际应从密钥交换中派生密钥）
    memcpy(ctx->encryption_ctx.encryption_key, ctx->kex_ctx.session_key, 
           sizeof(ctx->encryption_ctx.encryption_key));
    memcpy(ctx->encryption_ctx.decryption_key, ctx->kex_ctx.session_key, 
           sizeof(ctx->encryption_ctx.decryption_key));
    memcpy(ctx->encryption_ctx.encryption_iv, ctx->kex_ctx.iv_client_to_server, 
           sizeof(ctx->encryption_ctx.encryption_iv));
    memcpy(ctx->encryption_ctx.decryption_iv, ctx->kex_ctx.iv_server_to_client, 
           sizeof(ctx->encryption_ctx.decryption_iv));
    ctx->encryption_ctx.key_len = ctx->kex_ctx.session_key_len;
    ctx->encryption_ctx.encryption_enabled = 1;
    ctx->encryption_ctx.decryption_enabled = 1;
    
    ctx->encryption_enabled = 1;
    ctx->state = SSH_STATE_ENCRYPTED;
    return SSH_OK;
}

// 处理密钥交换
// 处理密钥交换（参考v4成功实现）
ssh_result_t handle_key_exchange(ssh_client_context_final_t *ctx) {
    ssh_result_t result;
    
    log_message(LOG_INFO, "Starting key exchange process");
    
    // 使用简化的密钥交换实现（参考v4版本）
    result = ssh_perform_key_exchange(ctx->socket_fd, &ctx->kex_ctx, 
                                      &ctx->local_version, &ctx->server_version);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Key exchange failed");
        return result;
    }
    
    log_message(LOG_INFO, "SSH key exchange completed successfully");
    
    // 启用连接加密
    result = enable_connection_encryption(ctx);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to enable connection encryption");
        return result;
    }
    
    ctx->state = SSH_STATE_ENCRYPTED;
    return SSH_OK;
}

// 处理用户认证
ssh_result_t handle_user_authentication(ssh_client_context_final_t *ctx) {
    ssh_result_t result;
    
    // 获取用户输入
    char username[64];
    char password[128];
    
    printf("Username: ");
    if (fgets(username, sizeof(username), stdin) == NULL) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 移除换行符
    char *newline = strchr(username, '\n');
    if (newline) *newline = '\0';
    
    printf("Password: ");
    // 简单的密码输入（实际应用中应该隐藏输入）
    if (fgets(password, sizeof(password), stdin) == NULL) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 移除换行符
    newline = strchr(password, '\n');
    if (newline) *newline = '\0';
    
    // 设置认证请求
    strncpy(ctx->auth_ctx.auth_request.username, username, sizeof(ctx->auth_ctx.auth_request.username) - 1);
    ctx->auth_ctx.auth_request.username[sizeof(ctx->auth_ctx.auth_request.username) - 1] = '\0';
    
    strncpy(ctx->auth_ctx.auth_request.service, "ssh-connection", sizeof(ctx->auth_ctx.auth_request.service) - 1);
    ctx->auth_ctx.auth_request.service[sizeof(ctx->auth_ctx.auth_request.service) - 1] = '\0';
    
    strncpy(ctx->auth_ctx.auth_request.method, "password", sizeof(ctx->auth_ctx.auth_request.method) - 1);
    ctx->auth_ctx.auth_request.method[sizeof(ctx->auth_ctx.auth_request.method) - 1] = '\0';
    
    strncpy(ctx->auth_ctx.auth_request.password, password, sizeof(ctx->auth_ctx.auth_request.password) - 1);
    ctx->auth_ctx.auth_request.password[sizeof(ctx->auth_ctx.auth_request.password) - 1] = '\0';
    
    // 创建认证请求消息
    uint8_t auth_request_buffer[MAX_BUFFER_SIZE];
    uint32_t auth_request_len;
    result = auth_create_request(&ctx->auth_ctx, auth_request_buffer, 
                                sizeof(auth_request_buffer), &auth_request_len);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to create authentication request");
        return result;
    }
    
    // 发送认证请求
    result = send_encrypted_data(ctx, (char*)auth_request_buffer, auth_request_len);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to send authentication request");
        return result;
    }
    
    // 接收认证响应
    char response_buffer[MAX_BUFFER_SIZE];
    size_t response_len;
    result = receive_and_decrypt_data(ctx, response_buffer, sizeof(response_buffer), &response_len);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to receive authentication response");
        return result;
    }
    
    // 检查响应类型
    if (response_len > 0 && (uint8_t)response_buffer[0] == SSH_MSG_USERAUTH_SUCCESS) {
        log_message(LOG_INFO, "Authentication successful");
        ctx->state = SSH_STATE_CONNECTION;
        return SSH_OK;
    } else if (response_len > 0 && (uint8_t)response_buffer[0] == SSH_MSG_USERAUTH_FAILURE) {
        log_message(LOG_ERROR, "Authentication failed");
        return SSH_ERROR_AUTH;
    } else {
        log_message(LOG_ERROR, "Unexpected authentication response");
        return SSH_ERROR_PROTOCOL;
    }
}

// 处理已认证连接的数据传输
ssh_result_t handle_connection_data(ssh_client_context_final_t *ctx) {
    char input_buffer[MAX_MESSAGE_SIZE];
    char receive_buffer[MAX_BUFFER_SIZE];
    fd_set read_fds;
    struct timeval timeout;
    
    printf("Connected to SSH server. Type messages (quit/exit to disconnect):\n");
    
    while (running) {
        FD_ZERO(&read_fds);
        FD_SET(ctx->socket_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int max_fd = (ctx->socket_fd > STDIN_FILENO) ? ctx->socket_fd : STDIN_FILENO;
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno != EINTR) {
                log_message(LOG_ERROR, "Select error: %s", strerror(errno));
                return SSH_ERROR_NETWORK;
            }
            continue;
        }
        
        if (activity == 0) {
            // 超时，继续循环
            continue;
        }
        
        // 处理服务器数据
        if (FD_ISSET(ctx->socket_fd, &read_fds)) {
            size_t received;
            ssh_result_t result = receive_and_decrypt_data(ctx, receive_buffer, sizeof(receive_buffer) - 1, &received);
            if (result != SSH_OK) {
                if (result == SSH_ERROR_CONNECTION_LOST) {
                    log_message(LOG_INFO, "Connection closed by server");
                    return SSH_OK;
                }
                return result;
            }
            
            if (received > 0) {
                receive_buffer[received] = '\0';
                printf("%s", receive_buffer);
                fflush(stdout);
            }
        }
        
        // 处理用户输入
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
                continue;
            }
            
            // 移除换行符
            char *newline = strchr(input_buffer, '\n');
            if (newline) *newline = '\0';
            
            // 检查退出命令
            if (strcmp(input_buffer, "quit") == 0 || strcmp(input_buffer, "exit") == 0) {
                log_message(LOG_INFO, "User requested disconnect");
                return SSH_ERROR_CONNECTION_LOST;
            }
            
            // 发送用户输入到服务器
            strcat(input_buffer, "\n");
            ssh_result_t result = send_encrypted_data(ctx, input_buffer, strlen(input_buffer));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send data to server");
                return result;
            }
        }
    }
    
    return SSH_OK;
}

// 连接到服务器
ssh_result_t connect_to_ssh_server(ssh_client_context_final_t *ctx, const char *server_host, int server_port) {
    struct sockaddr_in server_addr;
    
    // 创建套接字
    ctx->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->socket_fd < 0) {
        log_message(LOG_ERROR, "Failed to create socket: %s", strerror(errno));
        return SSH_ERROR_NETWORK;
    }
    
    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    
    if (inet_pton(AF_INET, server_host, &server_addr.sin_addr) <= 0) {
        log_message(LOG_ERROR, "Invalid address: %s", server_host);
        close(ctx->socket_fd);
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 连接到服务器
    if (connect(ctx->socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_message(LOG_ERROR, "Failed to connect to server: %s", strerror(errno));
        close(ctx->socket_fd);
        return SSH_ERROR_NETWORK;
    }
    
    ctx->connected = 1;
    log_message(LOG_INFO, "Connected to server %s:%d", server_host, server_port);
    return SSH_OK;
}

// 主函数
int main(int argc, char *argv[]) {
    const char *server_host = SERVER_IP;
    int server_port = SSH_PORT;
    
    // 解析命令行参数
    if (argc >= 2) {
        server_host = argv[1];
    }
    if (argc >= 3) {
        server_port = atoi(argv[2]);
    }
    
    printf("Final SSH Client\n");
    printf("Connecting to %s:%d\n", server_host, server_port);
    
    // 初始化日志
    init_logger(LOG_DEBUG);
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 初始化客户端上下文
    ssh_client_context_final_t ctx;
    ssh_result_t result = init_ssh_client_context(&ctx);
    if (result != SSH_OK) {
        fprintf(stderr, "Failed to initialize SSH client context\n");
        return 1;
    }
    
    // 连接到服务器
    result = connect_to_ssh_server(&ctx, server_host, server_port);
    if (result != SSH_OK) {
        fprintf(stderr, "Failed to connect to server\n");
        return 1;
    }
    
    // 执行版本交换
    if (ctx.state == SSH_STATE_VERSION_EXCHANGE) {
        result = handle_version_exchange(&ctx);
        if (result != SSH_OK) {
            fprintf(stderr, "Version exchange failed\n");
            close(ctx.socket_fd);
            return 1;
        }
    }
    
    // 执行密钥交换
    if (ctx.state == SSH_STATE_KEY_EXCHANGE) {
        result = handle_key_exchange(&ctx);
        if (result != SSH_OK) {
            fprintf(stderr, "Key exchange failed\n");
            close(ctx.socket_fd);
            return 1;
        }
    }
    
    // 执行用户认证
    if (ctx.state == SSH_STATE_ENCRYPTED) {
        result = handle_user_authentication(&ctx);
        if (result != SSH_OK) {
            fprintf(stderr, "User authentication failed\n");
            close(ctx.socket_fd);
            return 1;
        }
    }
    
    // 进入主连接循环
    if (ctx.state == SSH_STATE_CONNECTION) {
        printf("SSH connection established with encryption\n");
        result = handle_connection_data(&ctx);
    }
    
    // 清理资源
    if (ctx.encryption_enabled) {
        // 安全清零加密密钥
        memset(&ctx.encryption_ctx, 0, sizeof(ssh_encryption_context_t));
    }
    
    if (ctx.socket_fd >= 0) {
        close(ctx.socket_fd);
    }
    
    auth_cleanup(&ctx.auth_ctx);
    
    if (result == SSH_OK) {
        printf("Disconnected from server\n");
        return 0;
    } else {
        fprintf(stderr, "Connection error: %s\n", ssh_error_string(result));
        return 1;
    }
}