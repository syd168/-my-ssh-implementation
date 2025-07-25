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

#define SSH_PORT 2222
#define SERVER_IP "127.0.0.1"

// SSH客户端上下文
typedef struct {
    int socket_fd;
    ssh_version_info_t local_version;
    ssh_version_info_t server_version;
    ssh_protocol_state_t state;
    ssh_kex_context_t kex_ctx;
    ssh_encryption_context_t encryption_ctx;  // 添加加密上下文
    int connected;
    int encryption_enabled;  // 添加加密启用标志
} ssh_client_context_t;

static int running = 1;

// 信号处理函数
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_message(LOG_INFO, "Received shutdown signal");
        running = 0;
    }
}

// 初始化SSH客户端上下文
ssh_result_t init_ssh_client_context(ssh_client_context_t *ctx) {
    memset(ctx, 0, sizeof(ssh_client_context_t));
    ctx->socket_fd = -1;
    ctx->state = SSH_STATE_VERSION_EXCHANGE;
    ctx->encryption_enabled = 0;  // 初始化加密状态
    
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
    
    return SSH_OK;
}

// 清理SSH客户端上下文
void cleanup_ssh_client_context(ssh_client_context_t *ctx) {
    if (ctx->socket_fd >= 0) {
        close(ctx->socket_fd);
        ctx->socket_fd = -1;
    }
    
    kex_cleanup(&ctx->kex_ctx);
    ctx->connected = 0;
}

// 连接到SSH服务器
ssh_result_t connect_to_ssh_server(ssh_client_context_t *ctx, 
                                   const char *server_ip, int port) {
    log_message(LOG_INFO, "Starting SSH Client v3, connecting to %s:%d", server_ip, port);
    
    ctx->socket_fd = connect_to_server(server_ip, port);
    if (ctx->socket_fd < 0) {
        log_message(LOG_ERROR, "Failed to connect to SSH server");
        return SSH_ERROR_NETWORK;
    }
    
    log_message(LOG_INFO, "Successfully connected to SSH server %s:%d", server_ip, port);
    ctx->connected = 1;
    return SSH_OK;
}

// 启用连接加密
ssh_result_t enable_connection_encryption(ssh_client_context_t *ctx) {
    // 从KEX上下文获取共享密钥
    uint8_t *shared_secret = ctx->kex_ctx.shared_secret;
    uint32_t shared_secret_len = ctx->kex_ctx.shared_secret_len;
    
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
    memcpy(ctx->encryption_ctx.encryption_key, encryption_key, AES_256_KEY_SIZE);
    memcpy(ctx->encryption_ctx.decryption_key, decryption_key, AES_256_KEY_SIZE);
    memcpy(ctx->encryption_ctx.encryption_iv, encryption_iv, AES_IV_SIZE);
    memcpy(ctx->encryption_ctx.decryption_iv, decryption_iv, AES_IV_SIZE);
    ctx->encryption_ctx.key_len = AES_256_KEY_SIZE;
    ctx->encryption_ctx.encryption_enabled = 1;
    ctx->encryption_ctx.decryption_enabled = 1;
    ctx->encryption_enabled = 1;
    
    log_message(LOG_INFO, "Connection encryption enabled");
    return SSH_OK;
}

// 执行SSH版本交换
ssh_result_t perform_version_exchange(ssh_client_context_t *ctx) {
    ssh_result_t result;
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    
    log_message(LOG_INFO, "Starting SSH version exchange...");
    
    // 发送客户端版本 (修复格式化截断警告)
    char version_line[SSH_VERSION_BUFFER_SIZE + 10];
    snprintf(version_line, sizeof(version_line), "%s\r\n", 
             ctx->local_version.full_version);
    
    result = send_data(ctx->socket_fd, version_line, strlen(version_line));
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to send SSH version");
        return result;
    }
    
    log_message(LOG_INFO, "Sending SSH version: %s", ctx->local_version.full_version);
    
    // 接收服务器版本
    result = receive_data(ctx->socket_fd, buffer, sizeof(buffer) - 1, &received);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to receive server version");
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
    
    // 解析服务器版本
    result = ssh_parse_version_string(buffer, &ctx->server_version);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to parse server version");
        return result;
    }
    
    // 检查兼容性
    if (!ssh_is_version_compatible(&ctx->server_version, &ctx->local_version)) {
        log_message(LOG_ERROR, "Incompatible SSH version");
        return SSH_ERROR_PROTOCOL;
    }
    
    log_message(LOG_INFO, "SSH version exchange completed successfully");
    log_message(LOG_INFO, "Server version: %s", buffer);
    
    ctx->state = SSH_STATE_KEY_EXCHANGE;
    return SSH_OK;
}

// 执行密钥交换
ssh_result_t perform_key_exchange(ssh_client_context_t *ctx) {
    ssh_result_t result;
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    
    log_message(LOG_INFO, "Starting SSH key exchange...");
    
    // 创建并发送KEXINIT消息
    uint8_t kexinit_buffer[MAX_BUFFER_SIZE];
    uint32_t kexinit_len;
    result = kex_create_kexinit(&ctx->kex_ctx, kexinit_buffer, 
                               sizeof(kexinit_buffer), &kexinit_len);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to create KEXINIT message");
        return result;
    }
    
    result = send_data(ctx->socket_fd, (char*)kexinit_buffer, kexinit_len);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to send KEXINIT message");
        return result;
    }
    
    // 接收服务器的KEXINIT消息
    result = receive_data(ctx->socket_fd, buffer, sizeof(buffer), &received);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to receive server KEXINIT");
        return SSH_ERROR_NETWORK;
    }
    
    // 解析服务器的KEXINIT消息
    result = kex_parse_kexinit(&ctx->kex_ctx, (uint8_t*)buffer, received);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to parse server KEXINIT message");
        return result;
    }
    
    // 协商算法
    result = kex_negotiate_algorithms(&ctx->kex_ctx);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Algorithm negotiation failed");
        return result;
    }
    
    // 生成DH密钥对
    result = dh_generate_keypair(&ctx->kex_ctx.dh_ctx);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to generate DH keypair");
        return result;
    }
    
    // 创建并发送KEXDH_INIT消息
    uint8_t dh_init_buffer[MAX_BUFFER_SIZE];
    uint32_t dh_init_len;
    result = kex_create_dh_init(&ctx->kex_ctx, dh_init_buffer,
                               sizeof(dh_init_buffer), &dh_init_len);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to create KEXDH_INIT message");
        return result;
    }
    
    result = send_data(ctx->socket_fd, (char*)dh_init_buffer, dh_init_len);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to send KEXDH_INIT message");
        return result;
    }
    
    // 接收服务器的KEXDH_REPLY消息
    result = receive_data(ctx->socket_fd, buffer, sizeof(buffer), &received);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to receive KEXDH_REPLY");
        return SSH_ERROR_NETWORK;
    }
    
    // 解析KEXDH_REPLY消息
    result = kex_parse_dh_reply(&ctx->kex_ctx, (uint8_t*)buffer, received);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to parse KEXDH_REPLY message");
        return result;
    }
    
    // 完成密钥交换
    result = kex_finish(&ctx->kex_ctx);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to finish key exchange");
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

// 运行SSH客户端循环
ssh_result_t run_ssh_client_loop(ssh_client_context_t *ctx) {
    char input_buffer[MAX_MESSAGE_SIZE];
    char receive_buffer[MAX_BUFFER_SIZE];
    char decrypted_buffer[MAX_BUFFER_SIZE];
    fd_set read_fds;
    
    // 接收连接建立确认消息
    size_t received;
    ssh_result_t result = receive_data(ctx->socket_fd, receive_buffer, 
                                      sizeof(receive_buffer) - 1, &received);
    if (result == SSH_OK && received > 0) {
        receive_buffer[received] = '\0';
        
        // 如果启用了加密，则先解密数据
        char *display_buffer = receive_buffer;
        if (ctx->encryption_enabled) {
            // 解密数据
            aes_context_t aes_ctx;
            aes_result_t aes_result = aes_init(&aes_ctx, 
                                              ctx->encryption_ctx.decryption_key, 
                                              ctx->encryption_ctx.key_len, 
                                              ctx->encryption_ctx.decryption_iv);
            
            if (aes_result == AES_SUCCESS) {
                int decrypted_len;
                aes_result = aes_decrypt_cbc(&aes_ctx, (unsigned char*)receive_buffer, 
                                           received, (unsigned char*)decrypted_buffer, &decrypted_len);
                aes_cleanup(&aes_ctx);
                
                if (aes_result == AES_SUCCESS) {
                    decrypted_buffer[decrypted_len] = '\0';
                    display_buffer = decrypted_buffer;
                }
            }
        }
        
        printf("SSH Server: %s", display_buffer);
    }
    
    printf("Connected to SSH server with encryption. Type messages (quit/exit to disconnect):\n");
    
    while (running && ctx->connected) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(ctx->socket_fd, &read_fds);
        
        struct timeval timeout = {1, 0};
        int activity = select(ctx->socket_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            log_message(LOG_ERROR, "Select error in client loop");
            break;
        }
        
        if (activity == 0) {
            continue; // 超时，继续循环
        }
        
        // 检查用户输入
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            printf("> ");
            fflush(stdout);
            
            if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) {
                break;
            }
            
            // 移除换行符
            size_t len = strlen(input_buffer);
            if (len > 0 && input_buffer[len-1] == '\n') {
                input_buffer[len-1] = '\0';
            }
            
            // 检查退出命令
            if (strcmp(input_buffer, "quit") == 0 || strcmp(input_buffer, "exit") == 0) {
                log_message(LOG_INFO, "Disconnecting from SSH server...");
                
                // 如果启用了加密，则加密发送退出命令
                if (ctx->encryption_enabled) {
                    unsigned char encrypted_cmd[MAX_BUFFER_SIZE];
                    int encrypted_len;
                    aes_context_t aes_ctx;
                    
                    aes_result_t aes_result = aes_init(&aes_ctx, 
                                                      ctx->encryption_ctx.encryption_key, 
                                                      ctx->encryption_ctx.key_len, 
                                                      ctx->encryption_ctx.encryption_iv);
                    
                    if (aes_result == AES_SUCCESS) {
                        aes_result = aes_encrypt_cbc(&aes_ctx, (const unsigned char*)input_buffer, 
                                                   strlen(input_buffer), encrypted_cmd, &encrypted_len);
                        aes_cleanup(&aes_ctx);
                        
                        if (aes_result == AES_SUCCESS) {
                            send_data(ctx->socket_fd, (char*)encrypted_cmd, encrypted_len);
                        } else {
                            send_data(ctx->socket_fd, input_buffer, strlen(input_buffer));
                        }
                    } else {
                        send_data(ctx->socket_fd, input_buffer, strlen(input_buffer));
                    }
                } else {
                    send_data(ctx->socket_fd, input_buffer, strlen(input_buffer));
                }
                break;
            }
            
            // 发送消息到服务器
            if (ctx->encryption_enabled) {
                // 加密发送消息
                unsigned char encrypted_msg[MAX_BUFFER_SIZE];
                int encrypted_len;
                aes_context_t aes_ctx;
                
                aes_result_t aes_result = aes_init(&aes_ctx, 
                                                  ctx->encryption_ctx.encryption_key, 
                                                  ctx->encryption_ctx.key_len, 
                                                  ctx->encryption_ctx.encryption_iv);
                
                if (aes_result == AES_SUCCESS) {
                    aes_result = aes_encrypt_cbc(&aes_ctx, (const unsigned char*)input_buffer, 
                                               strlen(input_buffer), encrypted_msg, &encrypted_len);
                    aes_cleanup(&aes_ctx);
                    
                    if (aes_result == AES_SUCCESS) {
                        result = send_data(ctx->socket_fd, (char*)encrypted_msg, encrypted_len);
                    } else {
                        result = send_data(ctx->socket_fd, input_buffer, strlen(input_buffer));
                    }
                } else {
                    result = send_data(ctx->socket_fd, input_buffer, strlen(input_buffer));
                }
            } else {
                result = send_data(ctx->socket_fd, input_buffer, strlen(input_buffer));
            }
            
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send message to server");
                break;
            }
        }
        
        // 检查服务器响应
        if (FD_ISSET(ctx->socket_fd, &read_fds)) {
            result = receive_data(ctx->socket_fd, receive_buffer, 
                                sizeof(receive_buffer) - 1, &received);
            if (result != SSH_OK || received <= 0) {
                log_message(LOG_INFO, "Connection closed by peer");
                break;
            }
            
            receive_buffer[received] = '\0';
            
            // 如果启用了加密，则先解密数据
            char *display_buffer = receive_buffer;
            if (ctx->encryption_enabled && received > 0) {
                // 解密数据
                aes_context_t aes_ctx;
                aes_result_t aes_result = aes_init(&aes_ctx, 
                                                  ctx->encryption_ctx.decryption_key, 
                                                  ctx->encryption_ctx.key_len, 
                                                  ctx->encryption_ctx.decryption_iv);
                
                if (aes_result == AES_SUCCESS) {
                    int decrypted_len;
                    aes_result = aes_decrypt_cbc(&aes_ctx, (unsigned char*)receive_buffer, 
                                               received, (unsigned char*)decrypted_buffer, &decrypted_len);
                    aes_cleanup(&aes_ctx);
                    
                    if (aes_result == AES_SUCCESS) {
                        decrypted_buffer[decrypted_len] = '\0';
                        display_buffer = decrypted_buffer;
                    }
                }
            }
            
            printf("SSH Server: %s", display_buffer);
        }
    }
    
    log_message(LOG_INFO, "SSH client disconnected");
    return SSH_OK;
}

int main(int argc, char *argv[]) {
    ssh_client_context_t client_ctx;
    ssh_result_t result;
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    const char *server_ip = (argc > 1) ? argv[1] : SERVER_IP;
    int port = (argc > 2) ? atoi(argv[2]) : SSH_PORT;
    
    // 初始化客户端上下文
    result = init_ssh_client_context(&client_ctx);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to initialize SSH client context");
        return 1;
    }
    
    // 连接到服务器
    result = connect_to_ssh_server(&client_ctx, server_ip, port);
    if (result != SSH_OK) {
        cleanup_ssh_client_context(&client_ctx);
        return 1;
    }
    
    // 执行版本交换
    result = perform_version_exchange(&client_ctx);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Version exchange failed");
        cleanup_ssh_client_context(&client_ctx);
        return 1;
    }
    
    // 执行密钥交换
    result = perform_key_exchange(&client_ctx);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Key exchange failed");
        cleanup_ssh_client_context(&client_ctx);
        return 1;
    }
    
    // 运行客户端循环
    result = run_ssh_client_loop(&client_ctx);
    
    // 清理资源
    cleanup_ssh_client_context(&client_ctx);
    
    log_message(LOG_INFO, "SSH Client v3 shutdown complete");
    return (result == SSH_OK) ? 0 : 1;
}