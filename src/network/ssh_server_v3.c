#include "../common/common.h"
#include "../network/socket_utils.h"
#include "../protocol/ssh_protocol.h"
#include "../protocol/kex.h"
#include "../crypto/aes.h"
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
    ssh_encryption_context_t encryption_ctx;  // 添加加密上下文
    int active;
    time_t connect_time;
    int encryption_enabled;  // 添加加密启用标志
} ssh_client_info_v3_t;

// 全局变量
static int server_socket = -1;
static ssh_client_info_v3_t clients[MAX_CLIENTS];
static int running = 1;

// 信号处理函数
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_message(LOG_INFO, "Received shutdown signal");
        running = 0;
    }
}

// 初始化客户端结构
void init_client(ssh_client_info_v3_t *client, int socket_fd, struct sockaddr_in *addr) {
    memset(client, 0, sizeof(ssh_client_info_v3_t));
    client->socket_fd = socket_fd;
    client->address = *addr;
    client->state = SSH_STATE_VERSION_EXCHANGE;
    client->active = 1;
    client->connect_time = time(NULL);
    client->encryption_enabled = 0;  // 初始化加密状态
    
    // 初始化SSH版本信息
    ssh_init_version_info(&client->version_info, 1); // 1 = server
    
    // 初始化KEX上下文
    kex_init(&client->kex_ctx, 1); // 1 = server
}

// 清理客户端连接
void cleanup_client(ssh_client_info_v3_t *client) {
    if (client->active) {
        log_message(LOG_INFO, "Closing SSH client connection (slot %ld)", 
                   client - clients);
        
        if (client->socket_fd >= 0) {
            close(client->socket_fd);
        }
        
        // 清理KEX上下文
        kex_cleanup(&client->kex_ctx);
        
        memset(client, 0, sizeof(ssh_client_info_v3_t));
        client->socket_fd = -1;
    }
}

// 发送SSH版本字符串
ssh_result_t send_ssh_version(ssh_client_info_v3_t *client) {
    char version_line[SSH_VERSION_BUFFER_SIZE + 10];
    snprintf(version_line, sizeof(version_line), "%s\r\n", 
             client->version_info.full_version);
    
    ssh_result_t result = send_data(client->socket_fd, version_line, strlen(version_line));
    if (result == SSH_OK) {
        log_message(LOG_INFO, "Sending SSH version: %s", client->version_info.full_version);
    }
    return result;
}

// 启用连接加密
ssh_result_t enable_connection_encryption(ssh_client_info_v3_t *client) {
    // 从KEX上下文获取共享密钥
    uint8_t *shared_secret = client->kex_ctx.shared_secret;
    uint32_t shared_secret_len = client->kex_ctx.shared_secret_len;
    
    // 简化实现：使用共享密钥的一部分作为加密密钥
    // 在实际SSH实现中，会使用更复杂的密钥派生函数
    unsigned char encryption_key[AES_256_KEY_SIZE];
    unsigned char decryption_key[AES_256_KEY_SIZE];
    unsigned char encryption_iv[AES_IV_SIZE];
    unsigned char decryption_iv[AES_IV_SIZE];
    
    // 生成密钥和IV（简化实现）
    memset(encryption_key, 0, AES_256_KEY_SIZE);
    memset(decryption_key, 0, AES_256_KEY_SIZE);
    memset(encryption_iv, 0, AES_IV_SIZE);
    memset(decryption_iv, 0, AES_IV_SIZE);
    
    // 使用共享密钥填充加密参数 (修复符号比较警告)
    for (uint32_t i = 0; i < AES_256_KEY_SIZE && i < shared_secret_len; i++) {
        encryption_key[i] = shared_secret[i];
        decryption_key[i] = shared_secret[i];
    }
    
    // 使用共享密钥的一部分作为IV (修复符号比较警告)
    for (uint32_t i = 0; i < AES_IV_SIZE && (i + AES_256_KEY_SIZE) < shared_secret_len; i++) {
        encryption_iv[i] = shared_secret[i + AES_256_KEY_SIZE];
        decryption_iv[i] = shared_secret[i + AES_256_KEY_SIZE];
    }
    
    // 启用加密
    memcpy(client->encryption_ctx.encryption_key, encryption_key, AES_256_KEY_SIZE);
    memcpy(client->encryption_ctx.decryption_key, decryption_key, AES_256_KEY_SIZE);
    memcpy(client->encryption_ctx.encryption_iv, encryption_iv, AES_IV_SIZE);
    memcpy(client->encryption_ctx.decryption_iv, decryption_iv, AES_IV_SIZE);
    client->encryption_ctx.key_len = AES_256_KEY_SIZE;
    client->encryption_ctx.encryption_enabled = 1;
    client->encryption_ctx.decryption_enabled = 1;
    client->encryption_enabled = 1;
    
    log_message(LOG_INFO, "Connection encryption enabled");
    return SSH_OK;
}

// 处理版本交换和密钥交换
ssh_result_t handle_version_and_kex(ssh_client_info_v3_t *client) {
    char buffer[MAX_BUFFER_SIZE];
    ssh_result_t result;
    
    if (client->state == SSH_STATE_VERSION_EXCHANGE) {
        log_message(LOG_INFO, "SSH client initialized, starting version exchange");
        
        // 发送服务器版本
        result = send_ssh_version(client);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send SSH version");
            return result;
        }
        
        // 接收客户端版本
        size_t received;
        result = receive_data(client->socket_fd, buffer, sizeof(buffer) - 1, &received);
        if (result != SSH_OK) {
            return SSH_ERROR_NETWORK;
        }
        
        buffer[received] = '\0';
        
        // 解析版本行
        char *line_end = strstr(buffer, "\r\n");
        if (line_end) {
            *line_end = '\0';
        } else {
            line_end = strchr(buffer, '\n');
            if (line_end) *line_end = '\0';
        }
        
        log_message(LOG_INFO, "Received SSH version line: %s", buffer);
        
        // 解析客户端版本
        ssh_version_info_t client_version;
        result = ssh_parse_version_string(buffer, &client_version);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to parse client version");
            return result;
        }
        
        // 检查兼容性
        if (!ssh_is_version_compatible(&client_version, &client->version_info)) {
            log_message(LOG_ERROR, "Incompatible SSH version");
            return SSH_ERROR_PROTOCOL;
        }
        
        log_message(LOG_INFO, "SSH version exchange completed successfully");
        log_message(LOG_INFO, "Client version: %s", buffer);
        
        client->state = SSH_STATE_KEY_EXCHANGE;
        return SSH_OK;
    }
    
    if (client->state == SSH_STATE_KEY_EXCHANGE) {
        log_message(LOG_INFO, "Starting SSH key exchange");
        
        // 等待客户端的KEXINIT消息
        size_t received;
        result = receive_data(client->socket_fd, buffer, sizeof(buffer), &received);
        if (result != SSH_OK) {
            return SSH_ERROR_NETWORK;
        }
        
        // 解析KEXINIT消息
        result = kex_parse_kexinit(&client->kex_ctx, (uint8_t*)buffer, received);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to parse KEXINIT message");
            return result;
        }
        
        // 发送服务器的KEXINIT消息
        uint8_t kexinit_buffer[MAX_BUFFER_SIZE];
        uint32_t kexinit_len;
        result = kex_create_kexinit(&client->kex_ctx, kexinit_buffer, 
                                   sizeof(kexinit_buffer), &kexinit_len);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to create KEXINIT message");
            return result;
        }
        
        result = send_data(client->socket_fd, (char*)kexinit_buffer, kexinit_len);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send KEXINIT message");
            return result;
        }
        
        // 协商算法
        result = kex_negotiate_algorithms(&client->kex_ctx);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Algorithm negotiation failed");
            return result;
        }
        
        // 等待客户端的KEXDH_INIT消息
        result = receive_data(client->socket_fd, buffer, sizeof(buffer), &received);
        if (result != SSH_OK) {
            return SSH_ERROR_NETWORK;
        }
        
        // 解析KEXDH_INIT消息
        result = kex_parse_dh_init(&client->kex_ctx, (uint8_t*)buffer, received);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to parse KEXDH_INIT message");
            return result;
        }
        
        // 创建并发送KEXDH_REPLY消息
        uint8_t dh_reply_buffer[MAX_BUFFER_SIZE];
        uint32_t dh_reply_len;
        result = kex_create_dh_reply(&client->kex_ctx, dh_reply_buffer,
                                    sizeof(dh_reply_buffer), &dh_reply_len);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to create KEXDH_REPLY message");
            return result;
        }
        
        result = send_data(client->socket_fd, (char*)dh_reply_buffer, dh_reply_len);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send KEXDH_REPLY message");
            return result;
        }
        
        // 完成密钥交换
        result = kex_finish(&client->kex_ctx);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to finish key exchange");
            return result;
        }
        
        log_message(LOG_INFO, "SSH key exchange completed successfully");
        
        // 启用连接加密
        result = enable_connection_encryption(client);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to enable connection encryption");
            return result;
        }
        
        client->state = SSH_STATE_ENCRYPTED;
        
        // 发送连接建立成功消息
        const char *success_msg = "SSH connection established with encryption!\n";
        if (client->encryption_enabled) {
            // 加密发送消息
            unsigned char encrypted_msg[MAX_BUFFER_SIZE];
            int encrypted_len;
            aes_context_t aes_ctx;
            
            // 初始化AES上下文用于加密
            aes_result_t aes_result = aes_init(&aes_ctx, 
                                              client->encryption_ctx.encryption_key, 
                                              client->encryption_ctx.key_len, 
                                              client->encryption_ctx.encryption_iv);
            
            if (aes_result == AES_SUCCESS) {
                aes_result = aes_encrypt_cbc(&aes_ctx, (const unsigned char*)success_msg, 
                                           strlen(success_msg), encrypted_msg, &encrypted_len);
                aes_cleanup(&aes_ctx);
                
                if (aes_result == AES_SUCCESS) {
                    send_data(client->socket_fd, (char*)encrypted_msg, encrypted_len);
                } else {
                    send_data(client->socket_fd, success_msg, strlen(success_msg));
                }
            } else {
                send_data(client->socket_fd, success_msg, strlen(success_msg));
            }
        } else {
            send_data(client->socket_fd, success_msg, strlen(success_msg));
        }
        
        return SSH_OK;
    }
    
    return SSH_OK;
}

// 处理已建立连接的数据传输
ssh_result_t handle_connection_data(ssh_client_info_v3_t *client) {
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    ssh_result_t result = receive_data(client->socket_fd, buffer, sizeof(buffer) - 1, &received);
    
    if (result != SSH_OK) {
        return SSH_ERROR_NETWORK;
    }
    
    buffer[received] = '\0';
    
    // 如果启用了加密，则先解密数据
    char *processed_data = buffer;
    char decrypted_buffer[MAX_BUFFER_SIZE];
    
    if (client->encryption_enabled && received > 0) {
        // 解密数据
        aes_context_t aes_ctx;
        aes_result_t aes_result = aes_init(&aes_ctx, 
                                          client->encryption_ctx.decryption_key, 
                                          client->encryption_ctx.key_len, 
                                          client->encryption_ctx.decryption_iv);
        
        if (aes_result == AES_SUCCESS) {
            int decrypted_len;
            aes_result = aes_decrypt_cbc(&aes_ctx, (unsigned char*)buffer, received, 
                                       (unsigned char*)decrypted_buffer, &decrypted_len);
            aes_cleanup(&aes_ctx);
            
            if (aes_result == AES_SUCCESS) {
                decrypted_buffer[decrypted_len] = '\0';
                processed_data = decrypted_buffer;
            }
        }
    }
    
    // 移除换行符
    char *newline = strchr(processed_data, '\n');
    if (newline) *newline = '\0';
    newline = strchr(processed_data, '\r');
    if (newline) *newline = '\0';
    
    log_message(LOG_INFO, "Received SSH data from client: %s", processed_data);
    
    // 检查断开连接命令
    if (strcmp(processed_data, "quit") == 0 || strcmp(processed_data, "exit") == 0) {
        log_message(LOG_INFO, "SSH client requested disconnect");
        return SSH_ERROR_CONNECTION_LOST;
    }
    
    // 回应客户端消息 (修复格式化截断警告)
    char response[MAX_BUFFER_SIZE];
    memset(response, 0, sizeof(response));
    
    // 安全地构建响应消息
    const char* prefix = "SSH Server received: ";
    const char* suffix = "\n";
    
    // 计算各部分的最大长度
    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    size_t max_data_len = sizeof(response) - prefix_len - suffix_len - 1; // -1 for null terminator
    
    // 构建响应消息
    strncpy(response, prefix, sizeof(response) - 1);
    response[sizeof(response) - 1] = '\0';
    
    // 添加处理后的数据，确保不会超出缓冲区
    size_t current_len = strlen(response);
    if (strlen(processed_data) > max_data_len) {
        strncat(response, processed_data, max_data_len);
    } else {
        strcat(response, processed_data);
    }
    
    // 添加后缀
    current_len = strlen(response);
    if (current_len < sizeof(response) - suffix_len) {
        strcat(response, suffix);
    }

    // 如果启用了加密，则加密响应数据
    if (client->encryption_enabled) {
        unsigned char encrypted_response[MAX_BUFFER_SIZE];
        int encrypted_len;
        aes_context_t aes_ctx;
        
        // 初始化AES上下文用于加密
        aes_result_t aes_result = aes_init(&aes_ctx, 
                                          client->encryption_ctx.encryption_key, 
                                          client->encryption_ctx.key_len, 
                                          client->encryption_ctx.encryption_iv);
        
        if (aes_result == AES_SUCCESS) {
            aes_result = aes_encrypt_cbc(&aes_ctx, (const unsigned char*)response, 
                                       strlen(response), encrypted_response, &encrypted_len);
            aes_cleanup(&aes_ctx);
            
            if (aes_result == AES_SUCCESS) {
                result = send_data(client->socket_fd, (char*)encrypted_response, encrypted_len);
            } else {
                result = send_data(client->socket_fd, response, strlen(response));
            }
        } else {
            result = send_data(client->socket_fd, response, strlen(response));
        }
    } else {
        result = send_data(client->socket_fd, response, strlen(response));
    }
    
    return result;
}

// 处理客户端连接
ssh_result_t handle_client_connection(ssh_client_info_v3_t *client) {
    ssh_result_t result = SSH_OK;
    
    if (client->state == SSH_STATE_VERSION_EXCHANGE || 
        client->state == SSH_STATE_KEY_EXCHANGE) {
        result = handle_version_and_kex(client);
    } else if (client->state == SSH_STATE_ENCRYPTED || 
               client->state == SSH_STATE_CONNECTION) {
        result = handle_connection_data(client);
    }
    
    if (result != SSH_OK) {
        if (result == SSH_ERROR_CONNECTION_LOST) {
            log_message(LOG_INFO, "SSH client disconnected");
        } else {
            log_message(LOG_ERROR, "Error handling client connection: %s", 
                       ssh_error_string(result));
        }
        cleanup_client(client);
    }
    
    return result;
}

// 查找空闲的客户端槽位
int find_free_client_slot() {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            return i;
        }
    }
    return -1;
}

// 接受新的客户端连接
void accept_new_client() {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
    if (client_socket < 0) {
        log_message(LOG_ERROR, "Failed to accept client connection");
        return;
    }
    
    int slot = find_free_client_slot();
    if (slot < 0) {
        log_message(LOG_WARN, "Maximum client connections reached");
        close(client_socket);
        return;
    }
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    log_message(LOG_INFO, "New SSH client connected from %s:%d (slot %d)", 
               client_ip, ntohs(client_addr.sin_port), slot);
    
    init_client(&clients[slot], client_socket, &client_addr);
}

int main(int argc, char *argv[]) {
    int port = SSH_PORT; // 默认端口
    
    // 检查是否有命令行参数指定端口
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            log_message(LOG_ERROR, "Invalid port number: %s. Using default port %d.", argv[1], SSH_PORT);
            port = SSH_PORT;
        }
    }
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    log_message(LOG_INFO, "Starting SSH Server v3 with encryption support on port %d", port);
    
    // 初始化客户端数组
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket_fd = -1;
        clients[i].active = 0;
    }
    
    // 创建服务器socket
    server_socket = create_server_socket(port);
    if (server_socket < 0) {
        log_message(LOG_ERROR, "Failed to create server socket");
        return 1;
    }
    
    log_message(LOG_INFO, "Server socket created and listening on port %d", port);
    log_message(LOG_INFO, "SSH Server v3 started on port %d", port);
    log_message(LOG_INFO, "SSH Protocol Version: SSH-2.0-MySSH_1.0");
    log_message(LOG_INFO, "Key Exchange: Diffie-Hellman Group 1");
    log_message(LOG_INFO, "Encryption: AES-256-CBC");
    log_message(LOG_INFO, "Waiting for SSH connections...");
    
    // 主事件循环
    while (running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(server_socket, &read_fds);
        
        int max_fd = server_socket;
        
        // 添加活跃的客户端socket到select集合
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].socket_fd >= 0) {
                FD_SET(clients[i].socket_fd, &read_fds);
                if (clients[i].socket_fd > max_fd) {
                    max_fd = clients[i].socket_fd;
                }
            }
        }
        
        struct timeval timeout = {1, 0}; // 1秒超时
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (running) {
                log_message(LOG_ERROR, "Select error");
            }
            break;
        }
        
        if (activity == 0) {
            continue; // 超时，继续循环
        }
        
        // 检查服务器socket是否有新连接
        if (FD_ISSET(server_socket, &read_fds)) {
            accept_new_client();
        }
        
        // 处理现有客户端的数据
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].socket_fd >= 0 && 
                FD_ISSET(clients[i].socket_fd, &read_fds)) {
                handle_client_connection(&clients[i]);
            }
        }
    }
    
    // 清理资源
    log_message(LOG_INFO, "Shutting down SSH Server v3...");
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        cleanup_client(&clients[i]);
    }
    
    if (server_socket >= 0) {
        close(server_socket);
    }
    
    log_message(LOG_INFO, "SSH Server v3 shutdown complete");
    return 0;
}