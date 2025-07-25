#include "../common/common.h"
#include "../network/socket_utils.h"
#include "../protocol/ssh_protocol.h"
#include "../protocol/kex.h"
#include "../protocol/auth.h"
#include "../protocol/channel.h"
#include "../app/ssh_app.h"
#include "../crypto/aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>
#include <time.h>

#define MAX_CLIENTS 10
#define SSH_PORT 2222
#define MAX_CHANNELS_PER_CLIENT 5

// 用户数据库
static user_info_t g_user_db[] = {
    {"testuser", "testpass"},
    {"admin", "admin123"},
    {"user", "password"}
};
static int g_user_count = 3;

// SSH客户端连接信息
typedef struct {
    int socket_fd;
    struct sockaddr_in address;
    ssh_version_info_t version_info;
    ssh_protocol_state_t state;
    ssh_kex_context_t kex_ctx;
    ssh_auth_context_t auth_ctx;
    ssh_channel_manager_t channel_manager;
    ssh_encryption_context_t encryption_ctx;
    int active;
    time_t connect_time;
    int encryption_enabled;
} ssh_client_info_final_t;

// 全局变量
static int server_socket = -1;
static ssh_client_info_final_t clients[MAX_CLIENTS];
static int running = 1;

// 信号处理函数
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_message(LOG_INFO, "Received shutdown signal");
        running = 0;
    }
}

// 初始化客户端结构
void init_client(ssh_client_info_final_t *client, int socket_fd, struct sockaddr_in *addr) {
    memset(client, 0, sizeof(ssh_client_info_final_t));
    client->socket_fd = socket_fd;
    client->address = *addr;
    client->state = SSH_STATE_VERSION_EXCHANGE;
    client->active = 1;
    client->connect_time = time(NULL);
    client->encryption_enabled = 0;
    
    // 初始化版本信息
    ssh_init_version_info(&client->version_info, 1); // 1 = server
    
    // 初始化KEX上下文
    kex_init(&client->kex_ctx, 1); // 1 = server
    
    // 初始化认证上下文
    auth_init(&client->auth_ctx);
    
    // 初始化通道管理器
    channel_manager_init(&client->channel_manager, MAX_CHANNELS_PER_CLIENT);
}

// 清理客户端资源
void cleanup_client(ssh_client_info_final_t *client) {
    if (client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }
    
    // 清理认证上下文
    auth_cleanup(&client->auth_ctx);
    
    // 清理通道管理器
    // 注意：这里应该清理所有通道，但为了简化，我们只清理管理器本身
    
    // 清理加密上下文
    if (client->encryption_enabled) {
        // 安全清零加密密钥
        memset(&client->encryption_ctx, 0, sizeof(ssh_encryption_context_t));
    }
    
    memset(client, 0, sizeof(ssh_client_info_final_t));
    client->socket_fd = -1;
}

// 发送数据（加密或明文）
ssh_result_t send_data_secure(ssh_client_info_final_t *client, const char *data, size_t len) {
    if (client->encryption_enabled) {
        // 加密数据
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

// 接收数据（解密或明文）
ssh_result_t receive_data_secure(ssh_client_info_final_t *client, char *buffer, size_t buffer_len, size_t *received) {
    ssh_result_t result = receive_data(client->socket_fd, buffer, buffer_len, received);
    if (result != SSH_OK) {
        return result;
    }
    
    if (client->encryption_enabled && *received > 0) {
        // 解密数据
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
ssh_result_t handle_version_exchange(ssh_client_info_final_t *client) {
    ssh_result_t result;
    
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

// 启用连接加密
ssh_result_t enable_connection_encryption(ssh_client_info_final_t *client) {
    // 初始化加密上下文（简化实现，实际应从密钥交换中派生密钥）
    memcpy(client->encryption_ctx.encryption_key, client->kex_ctx.session_key, 
           sizeof(client->encryption_ctx.encryption_key));
    memcpy(client->encryption_ctx.decryption_key, client->kex_ctx.session_key, 
           sizeof(client->encryption_ctx.decryption_key));
    memcpy(client->encryption_ctx.encryption_iv, client->kex_ctx.iv_server_to_client, 
           sizeof(client->encryption_ctx.encryption_iv));
    memcpy(client->encryption_ctx.decryption_iv, client->kex_ctx.iv_client_to_server, 
           sizeof(client->encryption_ctx.decryption_iv));
    client->encryption_ctx.key_len = client->kex_ctx.session_key_len;
    client->encryption_ctx.encryption_enabled = 1;
    client->encryption_ctx.decryption_enabled = 1;
    
    client->encryption_enabled = 1;
    client->state = SSH_STATE_ENCRYPTED;
    return SSH_OK;
}

// 处理密钥交换（参考v4成功实现）
ssh_result_t handle_key_exchange(ssh_client_info_final_t *client) {
    ssh_result_t result;
    
    log_message(LOG_INFO, "Starting key exchange process");
    
    // 使用简化的密钥交换实现（参考v4版本）
    result = ssh_perform_key_exchange(client->socket_fd, &client->kex_ctx, 
                                      &client->version_info, &client->version_info);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Key exchange failed");
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
    return SSH_OK;
}

// 处理用户认证
ssh_result_t handle_user_authentication(ssh_client_info_final_t *client) {
    ssh_result_t result;
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    
    // 接收认证请求
    result = receive_data_secure(client, buffer, sizeof(buffer), &received);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to receive authentication request");
        return result;
    }
    
    // 解析认证请求
    result = auth_parse_request(&client->auth_ctx, (uint8_t*)buffer, received);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to parse authentication request");
        return result;
    }
    
    // 验证凭据
    result = auth_verify_credentials(&client->auth_ctx, g_user_db, g_user_count);
    if (result != SSH_OK) {
        log_message(LOG_WARN, "Authentication failed for user: %s", 
                   client->auth_ctx.auth_request.username);
        
        // 发送认证失败消息
        uint8_t failure_buffer[256];
        uint32_t failure_len;
        result = auth_create_failure(failure_buffer, sizeof(failure_buffer), &failure_len);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to create authentication failure message");
            return result;
        }
        
        result = send_data_secure(client, (char*)failure_buffer, failure_len);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send authentication failure message");
            return result;
        }
        
        return SSH_ERROR_AUTH;
    }
    
    log_message(LOG_INFO, "User %s authenticated successfully", 
               client->auth_ctx.auth_request.username);
    
    // 发送认证成功消息
    uint8_t success_buffer[256];
    uint32_t success_len;
    result = auth_create_success(success_buffer, sizeof(success_buffer), &success_len);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to create authentication success message");
        return result;
    }
    
    result = send_data_secure(client, (char*)success_buffer, success_len);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to send authentication success message");
        return result;
    }
    
    client->state = SSH_STATE_CONNECTION;
    return SSH_OK;
}

// 处理已认证连接的数据
ssh_result_t handle_connection_data(ssh_client_info_final_t *client) {
    ssh_result_t result;
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    
    // 接收数据
    result = receive_data_secure(client, buffer, sizeof(buffer), &received);
    if (result != SSH_OK) {
        if (result == SSH_ERROR_CONNECTION_LOST) {
            log_message(LOG_INFO, "Client disconnected");
            return result;
        }
        log_message(LOG_ERROR, "Failed to receive data from client");
        return result;
    }
    
    if (received == 0) {
        return SSH_OK;
    }
    
    buffer[received] = '\0';
    log_message(LOG_DEBUG, "Received %zu bytes from client: %s", received, buffer);
    
    // 移除换行符
    char *newline = strchr(buffer, '\n');
    if (newline) *newline = '\0';
    newline = strchr(buffer, '\r');
    if (newline) *newline = '\0';
    
    // 处理特殊命令
    if (strcmp(buffer, "quit") == 0 || strcmp(buffer, "exit") == 0) {
        const char *bye_msg = "Goodbye!\n";
        result = send_data_secure(client, bye_msg, strlen(bye_msg));
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send goodbye message");
            return result;
        }
        log_message(LOG_INFO, "Client requested disconnect");
        return SSH_ERROR_CONNECTION_LOST;
    } else if (strcmp(buffer, "help") == 0) {
        const char *help_msg = 
            "Available commands:\n"
            "  help                    - Show this help message\n"
            "  whoami                  - Show current user\n"
            "  time                    - Show server time\n"
            "  echo <text>             - Echo text back\n"
            "  exec <command>          - Execute remote command on server\n"
            "  download <filename>     - Download file from server\n"
            "  upload <filename>       - Upload file to server\n"
            "  file <filename>         - Get test file content (demo)\n"
            "  quit/exit               - Disconnect\n"
            "\nExamples:\n"
            "  exec ls -la             - List files\n"
            "  exec pwd                - Show current directory\n"
            "  exec ps aux             - Show running processes\n"
            "  download /etc/hosts     - Download hosts file\n"
            "  upload myfile.txt       - Upload a file\n";
        result = send_data_secure(client, help_msg, strlen(help_msg));
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send help message");
            return result;
        }
    } else if (strcmp(buffer, "whoami") == 0) {
        char response[MAX_BUFFER_SIZE];
        snprintf(response, sizeof(response), "You are: %s\n", client->auth_ctx.auth_request.username);
        result = send_data_secure(client, response, strlen(response));
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send whoami response");
            return result;
        }
    } else if (strcmp(buffer, "time") == 0) {
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        char response[MAX_BUFFER_SIZE];
        snprintf(response, sizeof(response), "Server time: %s\n", time_str);
        result = send_data_secure(client, response, strlen(response));
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send time response");
            return result;
        }
    } else if (strncmp(buffer, "echo ", 5) == 0) {
        const char *echo_text = buffer + 5;
        char response[MAX_BUFFER_SIZE];
        snprintf(response, sizeof(response), "Echo: %s\n", echo_text);
        result = send_data_secure(client, response, strlen(response));
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send echo response");
            return result;
        }
    } else if (strncmp(buffer, "file ", 5) == 0) {
        // 简单的文件传输模拟
        const char *filename = buffer + 5;
        if (strcmp(filename, "test.txt") == 0) {
            const char *file_content = 
                "This is a test file.\n"
                "It contains multiple lines.\n"
                "File transfer simulation successful!\n";
            char response[MAX_BUFFER_SIZE];
            snprintf(response, sizeof(response), "File content of %s:\n%s", filename, file_content);
            result = send_data_secure(client, response, strlen(response));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send file content");
                return result;
            }
        } else {
            char response[MAX_BUFFER_SIZE];
            snprintf(response, sizeof(response), "File not found: %s\n", filename);
            result = send_data_secure(client, response, strlen(response));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send file not found response");
                return result;
            }
        }
    } else if (strncmp(buffer, "exec ", 5) == 0) {
        // 远程命令执行功能
        const char *command = buffer + 5;
        char response[MAX_BUFFER_SIZE];
        
        log_message(LOG_INFO, "Executing remote command: %s", command);
        
        // 使用popen执行命令并获取输出
        FILE *pipe = popen(command, "r");
        if (pipe == NULL) {
            snprintf(response, sizeof(response), "Error: Failed to execute command '%s'\n", command);
            result = send_data_secure(client, response, strlen(response));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send command error response");
                return result;
            }
        } else {
            // 读取命令输出
            char cmd_output[MAX_BUFFER_SIZE - 100]; // 留出空间给前缀
            size_t total_read = 0;
            size_t bytes_read;
            
            while ((bytes_read = fread(cmd_output + total_read, 1, 
                                     sizeof(cmd_output) - total_read - 1, pipe)) > 0) {
                total_read += bytes_read;
                if (total_read >= sizeof(cmd_output) - 1) break;
            }
            
            cmd_output[total_read] = '\0';
            int exit_code = pclose(pipe);
            
            // 发送命令输出
            if (total_read > 0) {
                snprintf(response, sizeof(response), "Command output:\n%s\nExit code: %d\n", 
                        cmd_output, WEXITSTATUS(exit_code));
            } else {
                snprintf(response, sizeof(response), "Command executed successfully (no output)\nExit code: %d\n", 
                        WEXITSTATUS(exit_code));
            }
            
            result = send_data_secure(client, response, strlen(response));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send command output");
                return result;
            }
        }
    } else if (strncmp(buffer, "download ", 9) == 0) {
        // 文件下载功能（从服务器发送文件到客户端）
        const char *filename = buffer + 9;
        
        log_message(LOG_INFO, "Client requesting file download: %s", filename);
        
        FILE *file = fopen(filename, "rb");
        if (file == NULL) {
            char response[MAX_BUFFER_SIZE];
            snprintf(response, sizeof(response), "Error: File '%s' not found or cannot be opened\n", filename);
            result = send_data_secure(client, response, strlen(response));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send file error response");
                return result;
            }
        } else {
            // 获取文件大小
            fseek(file, 0, SEEK_END);
            long file_size = ftell(file);
            fseek(file, 0, SEEK_SET);
            
            char header[256];
            snprintf(header, sizeof(header), "FILE_START:%s:%ld\n", filename, file_size);
            result = send_data_secure(client, header, strlen(header));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send file header");
                fclose(file);
                return result;
            }
            
            // 发送文件内容
            char file_buffer[1024];
            size_t bytes_read;
            size_t total_sent = 0;
            
            while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
                result = send_data_secure(client, file_buffer, bytes_read);
                if (result != SSH_OK) {
                    log_message(LOG_ERROR, "Failed to send file data");
                    fclose(file);
                    return result;
                }
                total_sent += bytes_read;
            }
            
            fclose(file);
            
            // 发送结束标记
            const char *end_marker = "\nFILE_END\n";
            result = send_data_secure(client, end_marker, strlen(end_marker));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send file end marker");
                return result;
            }
            
            log_message(LOG_INFO, "File download completed: %s (%zu bytes)", filename, total_sent);
        }
    } else if (strncmp(buffer, "upload ", 7) == 0) {
        // 文件上传功能（从客户端接收文件到服务器）
        const char *filename = buffer + 7;
        
        log_message(LOG_INFO, "Client initiating file upload: %s", filename);
        
        char response[MAX_BUFFER_SIZE];
        snprintf(response, sizeof(response), "Ready to receive file: %s\nSend file data followed by 'UPLOAD_END'\n", filename);
        result = send_data_secure(client, response, strlen(response));
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send upload ready response");
            return result;
        }
        
        // 注意：完整的上传实现需要状态管理，这里提供基本框架
        // 实际应用中需要在客户端状态中添加上传状态跟踪
    } else {
        // 简单回显数据（使用安全的字符串操作）
        char response[MAX_BUFFER_SIZE];
        const char* prefix = "Server received: ";
        const char* suffix = "\n";
        
        // 计算最大可容纳的输入数据长度
        size_t max_data_len = sizeof(response) - strlen(prefix) - strlen(suffix) - 1;
        
        // 构建响应
        strncpy(response, prefix, sizeof(response) - 1);
        response[sizeof(response) - 1] = '\0';
        
        size_t current_len = strlen(response);
        if (strlen(buffer) > max_data_len) {
            strncat(response, buffer, max_data_len);
        } else {
            strcat(response, buffer);
        }
        
        current_len = strlen(response);
        if (current_len < sizeof(response) - strlen(suffix)) {
            strcat(response, suffix);
        }

        result = send_data_secure(client, response, strlen(response));
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send response to client");
            return result;
        }
    }
    
    return SSH_OK;
}

// 处理客户端连接
ssh_result_t handle_client_connection(ssh_client_info_final_t *client) {
    ssh_result_t result = SSH_OK;
    
    // 使用事件驱动的状态机，而不是连续的while循环
    switch (client->state) {
        case SSH_STATE_VERSION_EXCHANGE:
            result = handle_version_exchange(client);
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Version exchange failed");
                return result;
            }
            break;
            
        case SSH_STATE_KEY_EXCHANGE:
            result = handle_key_exchange(client);
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Key exchange failed");
                return result;
            }
            break;
            
        case SSH_STATE_ENCRYPTED:
            result = handle_user_authentication(client);
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "User authentication failed");
                return result;
            }
            break;
            
        case SSH_STATE_CONNECTION:
        {
            // 静态变量跟踪是否已发送欢迎消息
                static int welcome_sent = 0;
                
                // 仅在首次进入连接状态时发送欢迎消息
                if (!welcome_sent) {
                    const char *welcome_msg = "Welcome to Final SSH Server! Type 'help' for available commands.\n";
                    result = send_data_secure(client, welcome_msg, strlen(welcome_msg));
                    if (result != SSH_OK) {
                        log_message(LOG_ERROR, "Failed to send welcome message");
                        return result;
                    }
                    welcome_sent = 1;
                }
                
                // 处理客户端数据
                result = handle_connection_data(client);
                if (result != SSH_OK) {
                    if (result == SSH_ERROR_CONNECTION_LOST) {
                        log_message(LOG_INFO, "Client disconnected normally");
                        return SSH_OK;
                    }
                    log_message(LOG_ERROR, "Error handling client data");
                    return result;
                }
                break;
            }
                
            default:
                log_message(LOG_ERROR, "Unknown SSH state: %d", client->state);
                return SSH_ERROR_PROTOCOL;
        }
    
    return SSH_OK;
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

// 主函数
int main() {
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    log_message(LOG_INFO, "Starting Final SSH Server with full functionality on port %d", SSH_PORT);
    
    // 初始化客户端数组
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket_fd = -1;
        clients[i].active = 0;
    }
    
    // 创建服务器socket
    server_socket = create_server_socket(SSH_PORT);
    if (server_socket < 0) {
        log_message(LOG_ERROR, "Failed to create server socket");
        return 1;
    }
    
    log_message(LOG_INFO, "Server socket created and listening on port %d", SSH_PORT);
    log_message(LOG_INFO, "SSH Final Server started on port %d", SSH_PORT);
    log_message(LOG_INFO, "SSH Protocol Version: %s", SSH_VERSION_STRING);
    log_message(LOG_INFO, "Key Exchange: Diffie-Hellman Group 1");
    log_message(LOG_INFO, "Encryption: AES-256-CBC");
    log_message(LOG_INFO, "Authentication: Password-based");
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
        
        // 检查是否有新的连接请求
        if (FD_ISSET(server_socket, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            
            int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
            if (client_socket < 0) {
                log_message(LOG_ERROR, "Failed to accept client connection");
                continue;
            }
            
            int slot = -1;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (!clients[i].active) {
                    slot = i;
                    break;
                }
            }
            
            if (slot < 0) {
                log_message(LOG_WARN, "Maximum client connections reached");
                close(client_socket);
                continue;
            }
            
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            
            log_message(LOG_INFO, "New SSH client connected from %s:%d (slot %d)", 
                       client_ip, ntohs(client_addr.sin_port), slot);
            
            // 设置客户端socket为非阻塞模式
            if (set_nonblocking(client_socket) < 0) {
                log_message(LOG_ERROR, "Failed to set client socket non-blocking");
                close(client_socket);
                continue;
            }
            
            init_client(&clients[slot], client_socket, &client_addr);
        }
        
        // 处理客户端数据
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].socket_fd >= 0 && 
                FD_ISSET(clients[i].socket_fd, &read_fds)) {
                
                ssh_result_t result = handle_client_connection(&clients[i]);
                if (result != SSH_OK) {
                    if (result == SSH_ERROR_CONNECTION_LOST) {
                        log_message(LOG_INFO, "Client disconnected (slot %d)", i);
                    } else {
                        log_message(LOG_ERROR, "Error handling SSH client (slot %d): %s", 
                                   i, ssh_error_string(result));
                    }
                    cleanup_client(&clients[i]);
                }
            }
        }
    }
    
    // 清理资源
    log_message(LOG_INFO, "Shutting down server...");
    if (server_socket >= 0) {
        close(server_socket);
    }
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            cleanup_client(&clients[i]);
        }
    }
    
    log_message(LOG_INFO, "Final SSH Server shutdown complete");
    printf("Final SSH Server shutdown complete\n");
    
    return 0;
}