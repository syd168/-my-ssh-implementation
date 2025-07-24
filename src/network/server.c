#include "socket_utils.h"

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    connection_state_t state;
    time_t connect_time;
} client_info_t;

// 处理客户端连接
static ssh_result_t handle_client(client_info_t *client) {
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    ssh_result_t result;
    
    // 接收客户端数据
    result = receive_data(client->client_fd, buffer, sizeof(buffer), &received);
    if (result != SSH_OK) {
        if (result == SSH_ERROR_CONNECTION_LOST) {
            log_message(LOG_INFO, "Client disconnected");
            client->state = CONN_DISCONNECTED;
        }
        return result;
    }
    
    if (received > 0) {
        log_message(LOG_INFO, "Received from client: %s", buffer);
        
        // 简单的回显服务器
        char response[MAX_BUFFER_SIZE];
        // 确保响应不会超出缓冲区大小
        int written = snprintf(response, sizeof(response), "Server received: %s", buffer);
        if (written >= (int)sizeof(response)) {
            log_message(LOG_WARN, "Response message truncated");
        }
        
        result = send_data(client->client_fd, response, strlen(response));
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send response to client: %s", 
                       ssh_error_string(result));
            client->state = CONN_ERROR;
            return result;
        }
        
        // 检查退出命令
        if (strncmp(buffer, "quit", 4) == 0 || strncmp(buffer, "exit", 4) == 0) {
            log_message(LOG_INFO, "Client requested disconnect");
            client->state = CONN_DISCONNECTED;
            return SSH_OK;
        }
    }
    
    return SSH_OK;
}

// 主服务器函数
int run_server(int port) {
    int server_fd;
    client_info_t clients[MAX_CONNECTIONS];
    fd_set read_fds, write_fds;
    struct timeval timeout;
    int max_fd;
    int activity;
    
    // 初始化客户端数组
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        clients[i].client_fd = -1;
        clients[i].state = CONN_DISCONNECTED;
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
    log_message(LOG_INFO, "Waiting for connections...");
    
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
                    clients[slot].client_fd = new_client_fd;
                    clients[slot].client_addr = client_addr;
                    clients[slot].state = CONN_CONNECTED;
                    clients[slot].connect_time = time(NULL);
                    
                    // 设置非阻塞模式
                    set_nonblocking(new_client_fd);
                    
                    log_message(LOG_INFO, "New client connected from %s:%d (slot %d)", 
                               inet_ntoa(client_addr.sin_addr), 
                               ntohs(client_addr.sin_port), slot);
                    
                    // 发送欢迎消息
                    const char *welcome = "Welcome to Simple SSH Server!\n";
                    send_data(new_client_fd, welcome, strlen(welcome));
                } else {
                    log_message(LOG_WARN, "Too many connections, rejecting new client");
                    close(new_client_fd);
                }
            }
        }
        
        // 处理客户端数据
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (clients[i].client_fd > 0 && clients[i].state == CONN_CONNECTED &&
                FD_ISSET(clients[i].client_fd, &read_fds)) {
                
                ssh_result_t result = handle_client(&clients[i]);
                if (result != SSH_OK || clients[i].state == CONN_DISCONNECTED) {
                    log_message(LOG_INFO, "Closing client connection (slot %d)", i);
                    close_socket(clients[i].client_fd);
                    clients[i].client_fd = -1;
                    clients[i].state = CONN_DISCONNECTED;
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
    
    return run_server(port);
}
