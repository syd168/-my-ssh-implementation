#include "../common/common.h"
#include "../network/socket_utils.h"
#include "../protocol/ssh_protocol.h"
#include "../protocol/kex.h"
#include "../crypto/aes.h"
#include "../protocol/ssh_encryption.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#define SSH_PORT 2222
#define SERVER_IP "127.0.0.1"

// SSH客户端上下文
typedef struct {
    int socket_fd;
    ssh_version_info_t local_version;
    ssh_version_info_t server_version;
    ssh_protocol_state_t state;
    ssh_kex_context_t kex_ctx;
    ssh_encryption_context_t encryption_ctx;
    int encryption_enabled;
    char server_host[256];
    int server_port;
} ssh_client_info_v4_t;

// 全局客户端上下文
static ssh_client_info_v4_t g_client;

// 信号处理函数
static volatile int g_running = 1;
static void signal_handler(int sig) {
    (void)sig; // 标记未使用参数
    g_running = 0;
}

// 初始化客户端
static void init_client(ssh_client_info_v4_t *client, const char *server_host, int server_port) {
    memset(client, 0, sizeof(ssh_client_info_v4_t));
    
    // 设置本地版本信息
    client->local_version.major_version = 2;
    client->local_version.minor_version = 0;
    strcpy(client->local_version.software_name, "SSHClient");
    strcpy(client->local_version.software_version, "v4.0");
    strcpy(client->local_version.comments, "Educational_SSH_Client");
    snprintf(client->local_version.full_version, sizeof(client->local_version.full_version),
             "SSH-%d.%d-%s_%s %s", 
             client->local_version.major_version,
             client->local_version.minor_version,
             client->local_version.software_name,
             client->local_version.software_version,
             client->local_version.comments);
    
    // 设置服务器信息
    strncpy(client->server_host, server_host, sizeof(client->server_host) - 1);
    client->server_host[sizeof(client->server_host) - 1] = '\0';
    client->server_port = server_port;
    
    client->state = SSH_STATE_VERSION_EXCHANGE;
}

// 处理SSH版本交换
static ssh_result_t handle_version_exchange(ssh_client_info_v4_t *client) {
    ssh_result_t result;
    
    // 发送版本字符串
    result = ssh_send_version_string(client->socket_fd, &client->local_version);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to send SSH version string");
        return result;
    }
    
    log_message(LOG_INFO, "Sent SSH version: %s", client->local_version.full_version);
    
    // 接收服务器版本字符串
    result = ssh_receive_version_string(client->socket_fd, &client->server_version);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to receive SSH version string");
        return result;
    }
    
    log_message(LOG_INFO, "Received SSH version: %s", client->server_version.full_version);
    
    // 检查版本兼容性
    if (client->server_version.major_version != 2 || client->server_version.minor_version != 0) {
        log_message(LOG_ERROR, "Incompatible SSH protocol version: %d.%d", 
                   client->server_version.major_version, client->server_version.minor_version);
        return SSH_ERROR_PROTOCOL;
    }
    
    client->state = SSH_STATE_KEY_EXCHANGE;
    return SSH_OK;
}

// 处理密钥交换
static ssh_result_t handle_key_exchange(ssh_client_info_v4_t *client) {
    ssh_result_t result;
    
    // 初始化密钥交换上下文
    result = kex_init(&client->kex_ctx, SSH_ROLE_CLIENT);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to initialize key交换上下文");
        return result;
    }
    
    // 执行密钥交换
    result = ssh_perform_key_exchange(client->socket_fd, &client->kex_ctx, 
                                      &client->local_version, &client->server_version);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Key exchange failed");
        return result;
    }
    
    log_message(LOG_INFO, "Key exchange completed successfully");
    
    // 检查会话密钥长度是否有效
    if (client->kex_ctx.session_key_len == 0) {
        log_message(LOG_ERROR, "Invalid session key length: %u", client->kex_ctx.session_key_len);
        return SSH_ERROR_CRYPTO;
    }
    
    // 初始化加密上下文
    result = ssh_enable_encryption(&client->kex_ctx.conn,
                                   client->kex_ctx.encryption_key_client_to_server,  // 客户端到服务器加密密钥
                                   client->kex_ctx.encryption_key_server_to_client,  // 服务器到客户端解密密钥
                                   client->kex_ctx.session_key_len,                  // 密钥长度
                                   client->kex_ctx.iv_client_to_server,              // 客户端到服务器加密IV
                                   client->kex_ctx.iv_server_to_client);             // 服务器到客户端解密IV
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to initialize encryption context");
        return result;
    }
    
    client->encryption_enabled = 1;
    client->state = SSH_STATE_ENCRYPTED;
    return SSH_OK;
}

// 发送加密数据
static ssh_result_t send_encrypted_data(ssh_client_info_v4_t *client, const char *data, size_t len) {
    if (client->encryption_enabled) {
        unsigned char encrypted_data[MAX_BUFFER_SIZE];
        int encrypted_len;
        aes_context_t aes_ctx;
        aes_result_t aes_result;
        
        // 初始化AES加密上下文
        aes_result = aes_init(&aes_ctx, 
                              client->encryption_ctx.encryption_key, 
                              client->encryption_ctx.key_len, 
                              client->encryption_ctx.encryption_iv);
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
        return send_data(client->socket_fd, (char*)encrypted_data, encrypted_len);
    } else {
        // 发送明文数据
        return send_data(client->socket_fd, data, len);
    }
}

// 接收并解密数据
static ssh_result_t receive_and_decrypt_data(ssh_client_info_v4_t *client, char *buffer, size_t buffer_len, size_t *received) {
    ssh_result_t result = receive_data(client->socket_fd, buffer, buffer_len, received);
    if (result != SSH_OK) {
        return result;
    }
    
    if (client->encryption_enabled && *received > 0) {
        unsigned char decrypted_data[MAX_BUFFER_SIZE];
        int decrypted_len;
        aes_context_t aes_ctx;
        aes_result_t aes_result;
        
        // 初始化AES解密上下文
        aes_result = aes_init(&aes_ctx, 
                              client->encryption_ctx.decryption_key, 
                              client->encryption_ctx.key_len, 
                              client->encryption_ctx.decryption_iv);
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
        
        // 复制解密后的数据到缓冲区
        if ((size_t)decrypted_len <= buffer_len) {
            memcpy(buffer, decrypted_data, decrypted_len);
            *received = decrypted_len;
        } else {
            log_message(LOG_ERROR, "Decrypted data too large for buffer");
            return SSH_ERROR_BUFFER_TOO_SMALL;
        }
    }
    
    return SSH_OK;
}

// 处理用户输入
static ssh_result_t handle_user_input(ssh_client_info_v4_t *client) {
    char input[MAX_BUFFER_SIZE];
    
    // 设置stdin为非阻塞模式
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);
    
    if (fgets(input, sizeof(input), stdin) != NULL) {
        // 移除换行符
        input[strcspn(input, "\n")] = 0;
        
        // 检查退出命令
        if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0) {
            log_message(LOG_INFO, "Client requested disconnect");
            return SSH_ERROR_CONNECTION_LOST;
        }
        
        // 发送数据
        size_t len = strlen(input);
        ssh_result_t result = send_encrypted_data(client, input, len);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send data");
            return result;
        }
        
        log_message(LOG_INFO, "Sent data: %s", input);
    }
    
    return SSH_OK;
}

// 处理接收的数据
static ssh_result_t handle_received_data(ssh_client_info_v4_t *client) {
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    
    ssh_result_t result = receive_and_decrypt_data(client, buffer, sizeof(buffer) - 1, &received);
    if (result != SSH_OK) {
        if (result == SSH_ERROR_CONNECTION_LOST) {
            log_message(LOG_INFO, "Server disconnected");
            return result;
        }
        log_message(LOG_ERROR, "Failed to receive data");
        return result;
    }
    
    if (received > 0) {
        buffer[received] = '\0';
        log_message(LOG_INFO, "Received data: %s", buffer);
        printf("Server response: %s\n", buffer);
        fflush(stdout);
    }
    
    return SSH_OK;
}

// 主连接循环
static ssh_result_t connection_loop(ssh_client_info_v4_t *client) {
    fd_set read_fds;
    struct timeval timeout;
    
    while (g_running) {
        FD_ZERO(&read_fds);
        FD_SET(client->socket_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int max_fd = (client->socket_fd > STDIN_FILENO) ? client->socket_fd : STDIN_FILENO;
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
        
        // 处理套接字数据
        if (FD_ISSET(client->socket_fd, &read_fds)) {
            ssh_result_t result = handle_received_data(client);
            if (result != SSH_OK) {
                if (result == SSH_ERROR_CONNECTION_LOST) {
                    log_message(LOG_INFO, "Connection closed by server");
                    return SSH_OK;
                }
                return result;
            }
        }
        
        // 处理用户输入
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            ssh_result_t result = handle_user_input(client);
            if (result != SSH_OK) {
                if (result == SSH_ERROR_CONNECTION_LOST) {
                    // 发送退出消息
                    send_encrypted_data(client, "quit", 4);
                    return SSH_OK;
                }
                return result;
            }
        }
    }
    
    return SSH_OK;
}

// 连接到服务器
static ssh_result_t connect_to_ssh_server(ssh_client_info_v4_t *client) {
    struct sockaddr_in server_addr;
    
    // 创建套接字
    client->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->socket_fd < 0) {
        log_message(LOG_ERROR, "Failed to create socket: %s", strerror(errno));
        return SSH_ERROR_NETWORK;
    }
    
    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(client->server_port);
    
    if (inet_pton(AF_INET, client->server_host, &server_addr.sin_addr) <= 0) {
        log_message(LOG_ERROR, "Invalid address: %s", client->server_host);
        close(client->socket_fd);
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 连接到服务器
    if (connect(client->socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_message(LOG_ERROR, "Failed to connect to server: %s", strerror(errno));
        close(client->socket_fd);
        return SSH_ERROR_NETWORK;
    }
    
    log_message(LOG_INFO, "Connected to server %s:%d", client->server_host, client->server_port);
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
    
    printf("SSH Client v4 (with encryption)\n");
    printf("Connecting to %s:%d\n", server_host, server_port);
    
    // 初始化日志
    init_logger(LOG_DEBUG);
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 初始化客户端
    init_client(&g_client, server_host, server_port);
    
    // 连接到服务器
    ssh_result_t result = connect_to_ssh_server(&g_client);
    if (result != SSH_OK) {
        fprintf(stderr, "Failed to connect to server\n");
        return 1;
    }
    
    // 执行版本交换
    result = handle_version_exchange(&g_client);
    if (result != SSH_OK) {
        fprintf(stderr, "Version exchange failed\n");
        close(g_client.socket_fd);
        return 1;
    }
    
    // 执行密钥交换
    result = handle_key_exchange(&g_client);
    if (result != SSH_OK) {
        fprintf(stderr, "Key exchange failed\n");
        close(g_client.socket_fd);
        return 1;
    }
    
    printf("SSH connection established with encryption\n");
    printf("Type 'quit' or 'exit' to disconnect\n");
    
    // 进入主循环
    result = connection_loop(&g_client);
    
    // 清理资源
    if (g_client.encryption_enabled) {
        // 注意：这里应该清理加密上下文，但目前没有提供清理函数
    }
    
    close(g_client.socket_fd);
    
    if (result == SSH_OK) {
        printf("Disconnected from server\n");
        return 0;
    } else {
        fprintf(stderr, "Connection error: %s\n", ssh_error_string(result));
        return 1;
    }
}