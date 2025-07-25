#include "socket_utils.h"
#include "../protocol/ssh_protocol.h"

typedef struct {
    int server_fd;
    connection_state_t state;
    ssh_connection_t ssh_conn;
    char server_host[256];
    int server_port;
} ssh_client_context_t;

// 处理SSH版本协商
static ssh_result_t handle_version_exchange(ssh_client_context_t *client) {
    ssh_result_t result;
    
    if (client->ssh_conn.state == SSH_STATE_VERSION_EXCHANGE) {
        // 首先发送我们的版本字符串
        result = ssh_send_version_string(client->server_fd, &client->ssh_conn.local_version);
        if (result != SSH_OK) {
            log_message(LOG_ERROR, "Failed to send SSH version string");
            return result;
        }
        
        // 接收服务器的版本字符串
        result = ssh_receive_version_string(client->server_fd, &client->ssh_conn.remote_version);
        if (result != SSH_OK) {
            if (result == SSH_ERROR_TIMEOUT) {
                // 服务器还没发送版本，继续等待
                return SSH_OK;
            }
            log_message(LOG_ERROR, "Failed to receive server SSH version string");
            return result;
        }
        
        // 检查版本兼容性
        if (!ssh_is_version_compatible(&client->ssh_conn.local_version, &client->ssh_conn.remote_version)) {
            log_message(LOG_ERROR, "SSH version incompatible with server");
            return SSH_ERROR_PROTOCOL;
        }
        
        log_message(LOG_INFO, "SSH version exchange completed successfully");
        log_message(LOG_INFO, "Server version: %s", client->ssh_conn.remote_version.full_version);
        
        // 版本协商完成，进入下一阶段
        client->ssh_conn.state = SSH_STATE_CONNECTION;
    }
    
    return SSH_OK;
}

// 处理用户输入
static ssh_result_t handle_user_input(ssh_client_context_t *client) {
    char input[MAX_MESSAGE_SIZE];
    
    // 设置stdin为非阻塞模式
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);
    
    if (fgets(input, sizeof(input), stdin) != NULL) {
        // 移除换行符
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) > 0) {
            ssh_result_t result = send_data(client->server_fd, input, strlen(input));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send SSH data to server: %s", 
                           ssh_error_string(result));
                client->state = CONN_ERROR;
                return result;
            }
            
            // 检查退出命令
            if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0) {
                log_message(LOG_INFO, "Disconnecting from SSH server...");
                client->state = CONN_DISCONNECTED;
            }
        }
    }
    
    // 恢复stdin的阻塞模式
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags);
    
    return SSH_OK;
}

// 处理服务器响应
static ssh_result_t handle_server_response(ssh_client_context_t *client) {
    char buffer[MAX_BUFFER_SIZE];
    size_t received;
    ssh_result_t result;
    
    result = receive_data(client->server_fd, buffer, sizeof(buffer), &received);
    if (result != SSH_OK) {
        if (result == SSH_ERROR_CONNECTION_LOST) {
            log_message(LOG_INFO, "SSH server disconnected");
            client->state = CONN_DISCONNECTED;
        }
        return result;
    }
    
    if (received > 0) {
        printf("SSH Server: %s\n", buffer);
        fflush(stdout);
    }
    
    return SSH_OK;
}

// 客户端主循环
static int run_ssh_client_loop(ssh_client_context_t *client) {
    fd_set read_fds;
    struct timeval timeout;
    int max_fd;
    int activity;
    int version_exchange_done = 0;
    
    while (client->state == CONN_CONNECTED) {
        // 处理版本协商
        if (!version_exchange_done) {
            ssh_result_t result = handle_version_exchange(client);
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "SSH version exchange failed: %s", ssh_error_string(result));
                client->state = CONN_ERROR;
                break;
            }
            
            if (client->ssh_conn.state == SSH_STATE_CONNECTION) {
                version_exchange_done = 1;
                printf("SSH connection established successfully!\n");
                printf("Connected to SSH server. Type messages (quit/exit to disconnect):\n");
                printf("> ");
                fflush(stdout);
            }
            
            // 在版本协商期间，不处理用户输入
            sleep(1);
            continue;
        }
        
        // 清空文件描述符集合
        FD_ZERO(&read_fds);
        
        // 添加服务器socket和stdin到读集合
        FD_SET(client->server_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        
        max_fd = (client->server_fd > STDIN_FILENO) ? client->server_fd : STDIN_FILENO;
        
        // 设置超时
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        // 等待活动
        activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0 && errno != EINTR) {
            log_message(LOG_ERROR, "Select error: %s", strerror(errno));
            client->state = CONN_ERROR;
            break;
        }
        
        if (activity == 0) {
            // 超时，继续循环
            continue;
        }
        
        // 检查是否有用户输入
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            ssh_result_t result = handle_user_input(client);
            if (result != SSH_OK && result != SSH_ERROR_CONNECTION_LOST) {
                break;
            }
            
            if (client->state == CONN_CONNECTED) {
                printf("> ");
                fflush(stdout);
            }
        }
        
        // 检查是否有服务器数据
        if (FD_ISSET(client->server_fd, &read_fds)) {
            ssh_result_t result = handle_server_response(client);
            if (result != SSH_OK && result != SSH_ERROR_CONNECTION_LOST) {
                break;
            }
            
            if (client->state == CONN_CONNECTED) {
                printf("> ");
                fflush(stdout);
            }
        }
    }
    
    return (client->state == CONN_DISCONNECTED) ? 0 : -1;
}

// 连接到SSH服务器
static ssh_result_t connect_to_ssh_server(ssh_client_context_t *client) {
    client->server_fd = connect_to_server(client->server_host, client->server_port);
    if (client->server_fd < 0) {
        client->state = CONN_ERROR;
        return SSH_ERROR_NETWORK;
    }
    
    // 设置非阻塞模式
    if (set_nonblocking(client->server_fd) < 0) {
        close_socket(client->server_fd);
        client->state = CONN_ERROR;
        return SSH_ERROR_NETWORK;
    }
    
    // 初始化SSH连接
    client->ssh_conn.socket_fd = client->server_fd;
    client->ssh_conn.state = SSH_STATE_VERSION_EXCHANGE;
    client->ssh_conn.is_server = 0;
    
    // 初始化本地版本信息
    ssh_result_t result = ssh_init_version_info(&client->ssh_conn.local_version, 0);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to initialize SSH version info");
        close_socket(client->server_fd);
        client->state = CONN_ERROR;
        return result;
    }
    
    client->state = CONN_CONNECTED;
    log_message(LOG_INFO, "Successfully connected to SSH server %s:%d", 
               client->server_host, client->server_port);
    log_message(LOG_INFO, "Starting SSH version exchange...");
    
    return SSH_OK;
}

// 主客户端函数
int run_ssh_client(const char *host, int port) {
    ssh_client_context_t client;
    ssh_result_t result;
    
    // 初始化客户端上下文
    memset(&client, 0, sizeof(client));
    strncpy(client.server_host, host, sizeof(client.server_host) - 1);
    client.server_port = port;
    client.state = CONN_DISCONNECTED;
    
    // 连接到SSH服务器
    result = connect_to_ssh_server(&client);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to connect to SSH server: %s", ssh_error_string(result));
        return -1;
    }
    
    // 运行客户端主循环
    int exit_code = run_ssh_client_loop(&client);
    
    // 清理资源
    if (client.server_fd >= 0) {
        close_socket(client.server_fd);
    }
    
    log_message(LOG_INFO, "SSH client disconnected");
    return exit_code;
}

int main(int argc, char *argv[]) {
    const char *host = "127.0.0.1";
    int port = DEFAULT_PORT;
    
    // 解析命令行参数
    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[2]);
            return 1;
        }
    }
    
    log_message(LOG_INFO, "Starting SSH Client, connecting to %s:%d", host, port);
    
    return run_ssh_client(host, port);
}
