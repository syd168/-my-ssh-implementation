#include "../common/common.h"
#include "../network/socket_utils.h"
#include "../protocol/auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>
#include <time.h>

#define MAX_CLIENTS 10
#define SSH_PORT 2222

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
    int authenticated;
    char username[64];
    int active;
    time_t connect_time;
} ssh_client_info_simple_t;

// 全局变量
static int server_socket = -1;
static ssh_client_info_simple_t clients[MAX_CLIENTS];
static int running = 1;

// 信号处理函数
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_message(LOG_INFO, "Received shutdown signal");
        running = 0;
    }
}

// 初始化客户端结构
void init_client(ssh_client_info_simple_t *client, int socket_fd, struct sockaddr_in *addr) {
    memset(client, 0, sizeof(ssh_client_info_simple_t));
    client->socket_fd = socket_fd;
    client->address = *addr;
    client->active = 1;
    client->connect_time = time(NULL);
    client->authenticated = 0;
}

// 清理客户端资源
void cleanup_client(ssh_client_info_simple_t *client) {
    if (client->socket_fd >= 0) {
        close(client->socket_fd);
        client->socket_fd = -1;
    }
    
    memset(client, 0, sizeof(ssh_client_info_simple_t));
    client->socket_fd = -1;
}

// 处理用户认证
ssh_result_t handle_user_authentication(ssh_client_info_simple_t *client) {
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    
    // 发送登录提示
    const char *login_prompt = "SSH Server Simple\nUsername: ";
    send_data(client->socket_fd, login_prompt, strlen(login_prompt));
    
    // 接收用户名
    ssh_result_t result = receive_data(client->socket_fd, buffer, sizeof(buffer), &received);
    if (result != SSH_OK) {
        return result;
    }
    
    buffer[received] = '\0';
    char *newline = strchr(buffer, '\n');
    if (newline) *newline = '\0';
    newline = strchr(buffer, '\r');
    if (newline) *newline = '\0';
    
    strncpy(client->username, buffer, sizeof(client->username) - 1);
    client->username[sizeof(client->username) - 1] = '\0';
    
    // 发送密码提示
    const char *password_prompt = "Password: ";
    send_data(client->socket_fd, password_prompt, strlen(password_prompt));
    
    // 接收密码
    result = receive_data(client->socket_fd, buffer, sizeof(buffer), &received);
    if (result != SSH_OK) {
        return result;
    }
    
    buffer[received] = '\0';
    newline = strchr(buffer, '\n');
    if (newline) *newline = '\0';
    newline = strchr(buffer, '\r');
    if (newline) *newline = '\0';
    
    // 验证凭据
    int authenticated = 0;
    for (int i = 0; i < g_user_count; i++) {
        if (strcmp(g_user_db[i].username, client->username) == 0 && 
            strcmp(g_user_db[i].password, buffer) == 0) {
            authenticated = 1;
            break;
        }
    }
    
    if (authenticated) {
        client->authenticated = 1;
        const char *success_msg = "Authentication successful!\n";
        send_data(client->socket_fd, success_msg, strlen(success_msg));
        log_message(LOG_INFO, "User %s authenticated successfully", client->username);
        return SSH_OK;
    } else {
        const char *failure_msg = "Authentication failed!\n";
        send_data(client->socket_fd, failure_msg, strlen(failure_msg));
        log_message(LOG_WARN, "Authentication failed for user: %s", client->username);
        return SSH_ERROR_AUTH;
    }
}

// 处理已认证连接的数据
ssh_result_t handle_connection_data(ssh_client_info_simple_t *client) {
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    
    // 接收数据
    ssh_result_t result = receive_data(client->socket_fd, buffer, sizeof(buffer), &received);
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
    
    // 移除换行符
    char *newline = strchr(buffer, '\n');
    if (newline) *newline = '\0';
    newline = strchr(buffer, '\r');
    if (newline) *newline = '\0';
    
    log_message(LOG_DEBUG, "Received from client %s: %s", client->username, buffer);
    
    // 处理特殊命令
    if (strcmp(buffer, "quit") == 0 || strcmp(buffer, "exit") == 0) {
        const char *bye_msg = "Goodbye!\n";
        send_data(client->socket_fd, bye_msg, strlen(bye_msg));
        log_message(LOG_INFO, "Client %s requested disconnect", client->username);
        return SSH_ERROR_CONNECTION_LOST;
    } else if (strcmp(buffer, "help") == 0) {
        const char *help_msg = 
            "Available commands:\n"
            "  help     - Show this help message\n"
            "  whoami   - Show current user\n"
            "  time     - Show server time\n"
            "  echo     - Echo text back\n"
            "  quit     - Disconnect\n"
            "  exit     - Disconnect\n";
        send_data(client->socket_fd, help_msg, strlen(help_msg));
    } else if (strcmp(buffer, "whoami") == 0) {
        char response[MAX_BUFFER_SIZE];
        snprintf(response, sizeof(response), "You are: %s\n", client->username);
        send_data(client->socket_fd, response, strlen(response));
    } else if (strcmp(buffer, "time") == 0) {
        time_t now = time(NULL);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        char response[MAX_BUFFER_SIZE];
        snprintf(response, sizeof(response), "Server time: %s\n", time_str);
        send_data(client->socket_fd, response, strlen(response));
    } else if (strncmp(buffer, "echo ", 5) == 0) {
        // 使用更安全的方式处理echo命令，避免缓冲区溢出
        const char *echo_text = buffer + 5;
        char response[MAX_BUFFER_SIZE];
        const char *prefix = "Echo: ";
        const char *suffix = "\n";
        
        // 计算最大可容纳的输入文本长度
        size_t max_text_len = sizeof(response) - strlen(prefix) - strlen(suffix) - 1;
        
        // 构建响应
        strncpy(response, prefix, sizeof(response) - 1);
        response[sizeof(response) - 1] = '\0';
        
        size_t current_len = strlen(response);
        if (strlen(echo_text) > max_text_len) {
            strncat(response, echo_text, max_text_len);
        } else {
            strcat(response, echo_text);
        }
        
        current_len = strlen(response);
        if (current_len < sizeof(response) - strlen(suffix)) {
            strcat(response, suffix);
        }
        
        send_data(client->socket_fd, response, strlen(response));
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
            send_data(client->socket_fd, response, strlen(response));
        } else {
            char response[MAX_BUFFER_SIZE];
            snprintf(response, sizeof(response), "File not found: %s\n", filename);
            send_data(client->socket_fd, response, strlen(response));
        }
    } else {
        // 简单回显数据，使用安全的字符串操作避免缓冲区溢出
        char response[MAX_BUFFER_SIZE];
        const char *prefix = "Server received: ";
        const char *suffix = "\n";
        
        // 计算最大可容纳的输入数据长度
        size_t max_data_len = sizeof(response) - strlen(prefix) - strlen(suffix) - 1;
        
        // 构建响应
        strncpy(response, prefix, sizeof(response) - 1);
        response[sizeof(response) - 1] = '\0';
        
        size_t current_len = strlen(response);
        if (received > max_data_len) {
            strncat(response, buffer, max_data_len);
        } else {
            strcat(response, buffer);
        }
        
        current_len = strlen(response);
        if (current_len < sizeof(response) - strlen(suffix)) {
            strcat(response, suffix);
        }
        
        send_data(client->socket_fd, response, strlen(response));
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
    
    log_message(LOG_INFO, "New client connected from %s:%d (slot %d)", 
               client_ip, ntohs(client_addr.sin_port), slot);
    
    init_client(&clients[slot], client_socket, &client_addr);
}

// 主函数
int main() {
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    log_message(LOG_INFO, "Starting Simple SSH Server on port %d", SSH_PORT);
    
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
    log_message(LOG_INFO, "Simple SSH Server started on port %d", SSH_PORT);
    log_message(LOG_INFO, "Waiting for connections...");
    
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
            accept_new_client();
        }
        
        // 处理客户端数据
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].socket_fd >= 0 && 
                FD_ISSET(clients[i].socket_fd, &read_fds)) {
                
                ssh_result_t result;
                
                // 如果未认证，先处理认证
                if (!clients[i].authenticated) {
                    result = handle_user_authentication(&clients[i]);
                    if (result != SSH_OK) {
                        log_message(LOG_INFO, "Authentication failed for client (slot %d)", i);
                        cleanup_client(&clients[i]);
                        continue;
                    }
                    
                    // 发送欢迎消息
                    const char *welcome_msg = "Welcome to Simple SSH Server!\nType 'help' for available commands.\n";
                    send_data(clients[i].socket_fd, welcome_msg, strlen(welcome_msg));
                } else {
                    // 处理已认证连接的数据
                    result = handle_connection_data(&clients[i]);
                    if (result != SSH_OK) {
                        if (result == SSH_ERROR_CONNECTION_LOST) {
                            log_message(LOG_INFO, "Client %s disconnected (slot %d)", 
                                       clients[i].username, i);
                        } else {
                            log_message(LOG_ERROR, "Error handling client %s data (slot %d)", 
                                       clients[i].username, i);
                        }
                        cleanup_client(&clients[i]);
                    }
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
    
    log_message(LOG_INFO, "Simple SSH Server shutdown complete");
    printf("Simple SSH Server shutdown complete\n");
    
    return 0;
}