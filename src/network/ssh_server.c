#include "socket_utils.h"
#include "../protocol/ssh_protocol.h"

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    connection_state_t state;
    ssh_connection_t ssh_conn;
    time_t connect_time;
} ssh_client_info_t;

// 处理SSH版本协商
static ssh_result_t handle_version_exchange(ssh_client_info_t *client) {
    ssh_result_t result;
    
    if (client->ssh_conn.state == SSH_STATE_VERSION_EXCHANGE) {
        // 首先发送我们的版本字符串
        result = ssh_send_version_string(client->client_fd, &client->ssh_conn.local_version);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send SSH version string");
            return result;
        }
        
        // 接收客户端的版本字符串
        result = ssh_receive_version_string(client->client_fd, &client->ssh_conn.remote_version);
        if (result != SSH_OK) {
            if (result == SSH_ERROR_TIMEOUT) {
                // 客户端还没发送版本，继续等待
                return SSH_OK;
            }
            log_message(LOG_ERROR, "Failed to receive client SSH version string");
            return result;
        }
        
        // 检查版本兼容性
        if (!ssh_is_version_compatible(&client->ssh_conn.local_version, &client->ssh_conn.remote_version)) {
            log_message(LOG_ERROR, "SSH version incompatible with client");
            return SSH_ERROR_PROTOCOL;
        }
        
        log_message(LOG_INFO, "SSH version exchange completed successfully");
        log_message(LOG_INFO, "Client version: %s", client->ssh_conn.remote_version.full_version);
        
        // 版本协商完成，进入下一阶段（目前是简单的连接状态）
        client->ssh_conn.state = SSH_STATE_CONNECTION;
        
        // 发送欢迎消息
        const char *welcome = "SSH connection established successfully!\n";
        return send_data(client->client_fd, welcome, strlen(welcome));
    }
    
    return SSH_OK;
}

// 处理已建立连接的客户端
static ssh_result_t handle_established_connection(ssh_client_info_t *client) {
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    ssh_result_t result;
    
    // 接收客户端数据
    result = receive_data(client->client_fd, buffer, sizeof(buffer), &received);
    if (result != SSH_OK) {
        if (result == SSH_ERROR_CONNECTION_LOST) {
            log_message(LOG_INFO, "SSH client disconnected");
            client->state = CONN_DISCONNECTED;
        }
        return result;
    }
    
    if (received > 0) {
        log_message(LOG_INFO, "Received SSH data from client: %s", buffer);
        
        // 简单的回显服务器
        char response[MAX_BUFFER_SIZE];
        // 确保响应不会超出缓冲区大小
        int written = snprintf(response, sizeof(response), "SSH Server received: %s", buffer);
        if (written >= (int)sizeof(response)) {
            log_message(LOG_WARN, "Response message truncated");
        }
        
        result = send_data(client->client_fd, response, strlen(response));
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send SSH response to client: %s", 
                       ssh_error_string(result));
            client->state = CONN_ERROR;
            return result;
        }
        
        // 检查退出命令
        if (strncmp(buffer, "quit", 4) == 0 || strncmp(buffer, "exit", 4) == 0) {
            log_message(LOG_INFO, "SSH client requested disconnect");
            client->state = CONN_DISCONNECTED;
            return SSH_OK;
        }
    }
    
    return SSH_OK;
}

// 处理客户端连接
static ssh_result_t handle_ssh_client(ssh_client_info_t *client) {
    ssh_result_t result;
    
    switch (client->ssh_conn.state) {
        case SSH_STATE_VERSION_EXCHANGE:
            result = handle_version_exchange(client);
            break;
            
        case SSH_STATE_CONNECTION:
            result = handle_established_connection(client);
            break;
            
        case SSH_STATE_DISCONNECTED:
            client->state = CONN_DISCONNECTED;
            result = SSH_OK;
            break;
            
        default:
            log_message(LOG_ERROR, "Unknown SSH protocol state: %d", client->ssh_conn.state);
            result = SSH_ERROR_PROTOCOL;
            break;
    }
    
    return result;
}

// 初始化SSH客户端信息
static ssh_result_t init_ssh_client(ssh_client_info_t *client, int client_fd, struct sockaddr_in *client_addr) {
    client->client_fd = client_fd;
    client->client_addr = *client_addr;
    client->state = CONN_CONNECTED;
    client->connect_time = time(NULL);
    
    // 初始化SSH连接
    client->ssh_conn.socket_fd = client_fd;
    client->ssh_conn.state = SSH_STATE_VERSION_EXCHANGE;
    client->ssh_conn.is_server = 1;
    
    // 初始化本地版本信息
    ssh_result_t result = ssh_init_version_info(&client->ssh_conn.local_version, 1);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to initialize SSH version info");
        return result;
    }
    
    log_message(LOG_INFO, "SSH client initialized, starting version exchange");
    return SSH_OK;
}

// 主服务器函数
int run_ssh_server(int port) {
    int server_fd;
    ssh_client_info_t clients[MAX_CONNECTIONS];
    fd_set read_fds, write_fds;
    struct timeval timeout;
    int max_fd;
    int activity;
    
    // 初始化客户端数组
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        clients[i].client_fd = -1;
        clients[i].state = CONN_DISCONNECTED;
        memset(&clients[i].ssh_conn, 0, sizeof(ssh_connection_t));
    }
    
    // 创建服务器socket
    server_fd = create_server_socket(port);
    if (server_fd < 0) {
        return -1;
    }
    
    // 设置非阻塞模式
    if (set_nonblocking(server_fd) < 0) {
        close_socket(server_fd);
        return -1;
    }
    
    log_message(LOG_INFO, "SSH Server started on port %d", port);
    log_message(LOG_INFO, "SSH Protocol Version: %s", SSH_VERSION_STRING);
    log_message(LOG_INFO, "Waiting for SSH connections...");
    
    while (1) {
        // 清空文件描述符集合
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        
        // 添加服务器socket到读集合
        FD_SET(server_fd, &read_fds);
        max_fd = server_fd;
        
        // 添加客户端socket到集合
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (clients[i].client_fd > 0 && clients[i].state == CONN_CONNECTED) {
                FD_SET(clients[i].client_fd, &read_fds);
                if (clients[i].client_fd > max_fd) {
                    max_fd = clients[i].client_fd;
                }
            }
        }
        
        // 设置超时
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        // 等待活动
        activity = select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            log_message(LOG_ERROR, "Select error: %s", strerror(errno));
            break;
        }
        
        if (activity == 0) {
            // 超时，继续循环
            continue;
        }
        
        // 检查服务器socket是否有新连接
        if (FD_ISSET(server_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);
            int new_client_fd;
            
            new_client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
            if (new_client_fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    log_message(LOG_ERROR, "Accept failed: %s", strerror(errno));
                }
            } else {
                // 查找空闲的客户端槽位
                int slot = -1;
                for (int i = 0; i < MAX_CONNECTIONS; i++) {
                    if (clients[i].state == CONN_DISCONNECTED) {
                        slot = i;
                        break;
                    }
                }
                
                if (slot >= 0) {
                    // 设置非阻塞模式
                    set_nonblocking(new_client_fd);
                    
                    // 初始化SSH客户端
                    ssh_result_t result = init_ssh_client(&clients[slot], new_client_fd, &client_addr);
                    if (result != SSH_OK) {
                        log_message(LOG_ERROR, "Failed to initialize SSH client");
                        close(new_client_fd);
                    } else {
                        log_message(LOG_INFO, "New SSH client connected from %s:%d (slot %d)", 
                                   inet_ntoa(client_addr.sin_addr), 
                                   ntohs(client_addr.sin_port), slot);
                    }
                } else {
                    log_message(LOG_WARN, "Too many SSH connections, rejecting new client");
                    close(new_client_fd);
                }
            }
        }
        
        // 处理客户端数据
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (clients[i].client_fd > 0 && clients[i].state == CONN_CONNECTED &&
                FD_ISSET(clients[i].client_fd, &read_fds)) {
                
                ssh_result_t result = handle_ssh_client(&clients[i]);
                if (result != SSH_OK || clients[i].state == CONN_DISCONNECTED) {
                    log_message(LOG_INFO, "Closing SSH client connection (slot %d)", i);
                    close_socket(clients[i].client_fd);
                    clients[i].client_fd = -1;
                    clients[i].state = CONN_DISCONNECTED;
                    clients[i].ssh_conn.state = SSH_STATE_DISCONNECTED;
                }
            }
        }
    }
    
    // 清理资源
    close_socket(server_fd);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (clients[i].client_fd > 0) {
            close_socket(clients[i].client_fd);
        }
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    
    // 解析命令行参数
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[1]);
            return 1;
        }
    }
    
    log_message(LOG_INFO, "Starting SSH Server on port %d", port);
    
    return run_ssh_server(port);
}
