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
#include <sys/select.h>

#define MAX_CLIENTS 10
#define SSH_PORT 2222

// SSH客户端连接信息
typedef struct {
    int socket_fd;
    struct sockaddr_in address;
    ssh_version_info_t version_info;
    ssh_protocol_state_t state;
    ssh_kex_context_t kex_ctx;
    ssh_encryption_context_t encryption_ctx;
    int encryption_enabled;
    time_t connect_time;
} ssh_client_info_v4_t;

// 全局服务器状态
static volatile int g_running = 1;
static ssh_client_info_v4_t g_clients[MAX_CLIENTS];

// 信号处理函数
static void signal_handler(int sig) {
    (void)sig; // 标记未使用参数
    g_running = 0;
    printf("\nShutting down server...\n");
}

// 初始化服务器版本信息
static void init_server_version(ssh_version_info_t *version) {
    version->major_version = 2;
    version->minor_version = 0;
    strcpy(version->software_name, "SSHServer");
    strcpy(version->software_version, "v4.0");
    strcpy(version->comments, "Educational_SSH_Server");
    snprintf(version->full_version, sizeof(version->full_version),
             "SSH-%d.%d-%s_%s %s", 
             version->major_version,
             version->minor_version,
             version->software_name,
             version->software_version,
             version->comments);
}

// 初始化客户端信息
static void init_client(ssh_client_info_v4_t *client) {
    memset(client, 0, sizeof(ssh_client_info_v4_t));
    client->socket_fd = -1;  // 初始化套接字为无效值
    init_server_version(&client->version_info);
    client->state = SSH_STATE_VERSION_EXCHANGE;
    client->connect_time = time(NULL);
}

// 处理SSH版本交换
static ssh_result_t handle_version_exchange(ssh_client_info_v4_t *client) {
    ssh_result_t result;
    
    // 检查套接字有效性
    if (client->socket_fd < 0) {
        log_message(LOG_ERROR, "Invalid socket file descriptor");
        return SSH_ERROR_NETWORK;
    }
    
    // 发送版本字符串
    result = ssh_send_version_string(client->socket_fd, &client->version_info);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to send SSH version string");
        return result;
    }
    
    log_message(LOG_INFO, "Sent SSH version: %s", client->version_info.full_version);
    
    // 接收客户端版本字符串
    ssh_version_info_t client_version;
    result = ssh_receive_version_string(client->socket_fd, &client_version);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to receive SSH version string");
        return result;
    }
    
    log_message(LOG_INFO, "Received SSH version: %s", client_version.full_version);
    
    // 检查版本兼容性
    if (client_version.major_version != 2 || client_version.minor_version != 0) {
        log_message(LOG_ERROR, "Incompatible SSH protocol version: %d.%d", 
                   client_version.major_version, client_version.minor_version);
        return SSH_ERROR_PROTOCOL;
    }
    
    client->state = SSH_STATE_KEY_EXCHANGE;
    return SSH_OK;
}

// 处理密钥交换
static ssh_result_t handle_key_exchange(ssh_client_info_v4_t *client) {
    ssh_result_t result;
    
    // 初始化密钥交换上下文
    result = kex_init(&client->kex_ctx, SSH_ROLE_SERVER);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to initialize key交换上下文");
        return result;
    }
    
    // 执行密钥交换
    result = ssh_perform_key_exchange(client->socket_fd, &client->kex_ctx, 
                                      &client->version_info, &client->version_info); // 简化处理
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Key exchange failed");
        return result;
    }
    
    log_message(LOG_INFO, "Key exchange completed successfully");
    
    // 初始化加密上下文
    // 修复：交换加密和解密密钥，因为对于服务器来说，它使用客户端到服务器的密钥来解密数据
    // 而使用服务器到客户端的密钥来加密数据
    result = ssh_enable_encryption(&client->kex_ctx.conn,
                                   client->kex_ctx.encryption_key_client_to_server,  // 客户端到服务器解密密钥
                                   client->kex_ctx.encryption_key_server_to_client,  // 服务器到客户端加密密钥
                                   client->kex_ctx.session_key_len,                  // 密钥长度
                                   client->kex_ctx.iv_client_to_server,              // 客户端到服务器解密IV
                                   client->kex_ctx.iv_server_to_client);             // 服务器到客户端加密IV
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
        
        // 初始化AES加密上下文，使用正确的加密密钥
        aes_result = aes_init(&aes_ctx, 
                              client->encryption_ctx.encryption_key,  // 使用加密密钥进行加密
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
        
        // 初始化AES解密上下文，使用正确的解密密钥
        aes_result = aes_init(&aes_ctx, 
                              client->encryption_ctx.decryption_key,  // 使用解密密钥进行解密
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

// 处理客户端数据
static ssh_result_t handle_client_data(ssh_client_info_v4_t *client) {
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    
    ssh_result_t result = receive_and_decrypt_data(client, buffer, sizeof(buffer) - 1, &received);
    if (result != SSH_OK) {
        if (result == SSH_ERROR_CONNECTION_LOST) {
            log_message(LOG_INFO, "Client disconnected");
            return result;
        }
        log_message(LOG_ERROR, "Failed to receive data from client");
        return result;
    }
    
    if (received > 0) {
        buffer[received] = '\0';
        
        // 移除换行符
        char *newline = strchr(buffer, '\n');
        if (newline) *newline = '\0';
        newline = strchr(buffer, '\r');
        if (newline) *newline = '\0';
        
        log_message(LOG_INFO, "Received data from client: %s", buffer);
        
        // 检查断开连接命令
        if (strcmp(buffer, "quit") == 0 || strcmp(buffer, "exit") == 0) {
            log_message(LOG_INFO, "Client requested disconnect");
            return SSH_ERROR_CONNECTION_LOST;
        }
        
        // 构造响应消息（安全的字符串处理）
        char response[MAX_BUFFER_SIZE];
        const char prefix[] = "Server received: ";
        size_t prefix_len = strlen(prefix);
        size_t buffer_len = strlen(buffer);
        size_t available_space = sizeof(response) - prefix_len - 2; // -2 for '\n' and '\0'
        
        // 安全地构造响应字符串
        strcpy(response, prefix);
        if (buffer_len > available_space) {
            // 截断过长的输入
            strncat(response, buffer, available_space);
        } else {
            strcat(response, buffer);
        }
        strcat(response, "\n");
        
        // 发送响应
        size_t response_len = strlen(response);
        result = send_encrypted_data(client, response, response_len);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send response to client");
            return result;
        }
        
        log_message(LOG_DEBUG, "Sent response to client: %s", response);
    }
    
    return SSH_OK;
}

// 清理客户端资源
static void cleanup_client(ssh_client_info_v4_t *client) {
    if (client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }
    
    if (client->encryption_enabled) {
        // 注意：这里应该清理加密上下文，但目前没有提供清理函数
        client->encryption_enabled = 0;
    }
    
    memset(client, 0, sizeof(ssh_client_info_v4_t));
    client->socket_fd = -1;
}

// 处理客户端连接
static ssh_result_t handle_client_connection(ssh_client_info_v4_t *client) {
    // 执行版本交换
    ssh_result_t result = handle_version_exchange(client);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Version exchange failed");
        return result;
    }
    
    // 执行密钥交换
    result = handle_key_exchange(client);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Key exchange failed");
        return result;
    }
    
    log_message(LOG_INFO, "SSH connection established with encryption");
    
    // 处理数据传输
    while (g_running) {
        fd_set read_fds;
        struct timeval timeout;
        
        FD_ZERO(&read_fds);
        FD_SET(client->socket_fd, &read_fds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(client->socket_fd + 1, &read_fds, NULL, NULL, &timeout);
        
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
        
        // 处理客户端数据
        if (FD_ISSET(client->socket_fd, &read_fds)) {
            result = handle_client_data(client);
            if (result != SSH_OK) {
                if (result == SSH_ERROR_CONNECTION_LOST) {
                    log_message(LOG_INFO, "Client disconnected normally");
                    return SSH_OK;
                }
                log_message(LOG_ERROR, "Error handling client data: %s", ssh_error_string(result));
                return result;
            }
        }
    }
    
    return SSH_OK;
}

// 接受新的客户端连接
static int accept_client(int server_fd, struct sockaddr_in *client_addr, socklen_t *client_addr_len) {
    int client_fd = accept(server_fd, (struct sockaddr*)client_addr, client_addr_len);
    if (client_fd < 0) {
        if (errno != EINTR) {
            log_message(LOG_ERROR, "Accept error: %s", strerror(errno));
        }
        return -1;
    }
    
    // 查找可用的客户端槽位
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].socket_fd < 0) {
            // 先初始化客户端结构体
            init_client(&g_clients[i]);
            // 然后设置套接字和地址信息
            g_clients[i].socket_fd = client_fd;
            g_clients[i].address = *client_addr;
            return i;
        }
    }
    
    // 没有可用槽位，拒绝连接
    log_message(LOG_WARN, "Maximum clients reached, rejecting connection");
    close(client_fd);
    return -1;
}

// 主函数
int main(int argc, char *argv[]) {
    int server_fd;
    struct sockaddr_in server_addr;
    int server_port = SSH_PORT;
    
    // 解析命令行参数
    if (argc >= 2) {
        server_port = atoi(argv[1]);
    }
    
    printf("SSH Server v4 (with encryption)\n");
    printf("Listening on port %d\n", server_port);
    
    // 初始化日志
    init_logger(LOG_DEBUG);
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 初始化客户端数组
    for (int i = 0; i < MAX_CLIENTS; i++) {
        g_clients[i].socket_fd = -1;
    }
    
    // 创建套接字
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log_message(LOG_ERROR, "Failed to create socket: %s", strerror(errno));
        return 1;
    }
    
    // 设置套接字选项
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message(LOG_ERROR, "Failed to set socket options: %s", strerror(errno));
        close(server_fd);
        return 1;
    }
    
    // 绑定地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server_port);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_message(LOG_ERROR, "Bind failed: %s", strerror(errno));
        close(server_fd);
        return 1;
    }
    
    // 开始监听
    if (listen(server_fd, 3) < 0) {
        log_message(LOG_ERROR, "Listen failed: %s", strerror(errno));
        close(server_fd);
        return 1;
    }
    
    log_message(LOG_INFO, "Server listening on port %d", server_port);
    
    // 主服务器循环
    while (g_running) {
        fd_set read_fds;
        struct timeval timeout;
        
        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int activity = select(server_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno != EINTR) {
                log_message(LOG_ERROR, "Select error: %s", strerror(errno));
                break;
            }
            continue;
        }
        
        if (activity == 0) {
            // 超时，继续循环
            continue;
        }
        
        // 处理新的连接请求
        if (FD_ISSET(server_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);
            
            int client_index = accept_client(server_fd, &client_addr, &client_addr_len);
            if (client_index >= 0) {
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                log_message(LOG_INFO, "New connection from %s:%d", client_ip, ntohs(client_addr.sin_port));
                
                // 处理客户端连接
                ssh_result_t result = handle_client_connection(&g_clients[client_index]);
                if (result != SSH_OK && result != SSH_ERROR_CONNECTION_LOST) {
                    log_message(LOG_ERROR, "Error handling client: %s", ssh_error_string(result));
                }
                
                // 清理客户端
                cleanup_client(&g_clients[client_index]);
            }
        }
    }
    
    // 清理所有客户端
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].socket_fd >= 0) {
            cleanup_client(&g_clients[i]);
        }
    }
    
    // 关闭服务器套接字
    close(server_fd);
    
    log_message(LOG_INFO, "Server shutdown complete");
    printf("Server shutdown complete\n");
    
    return 0;
}