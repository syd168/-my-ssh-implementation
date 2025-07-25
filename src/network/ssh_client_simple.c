#include "../common/common.h"
#include "../network/socket_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>

#define SSH_PORT 2222
#define SERVER_IP "127.0.0.1"

static int running = 1;
static int socket_fd = -1;

// 信号处理函数
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_message(LOG_INFO, "Received shutdown signal");
        running = 0;
    }
}

// 处理连接数据
ssh_result_t handle_connection_data() {
    char input_buffer[MAX_MESSAGE_SIZE];
    char receive_buffer[MAX_BUFFER_SIZE];
    fd_set read_fds;
    struct timeval timeout;
    
    printf("Connected to Simple SSH Server. Type messages (quit/exit to disconnect):\n");
    
    while (running) {
        FD_ZERO(&read_fds);
        FD_SET(socket_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int max_fd = (socket_fd > STDIN_FILENO) ? socket_fd : STDIN_FILENO;
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
        if (FD_ISSET(socket_fd, &read_fds)) {
            size_t received;
            ssh_result_t result = receive_data(socket_fd, receive_buffer, sizeof(receive_buffer) - 1, &received);
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
            
            // 发送用户输入到服务器
            ssh_result_t result = send_data(socket_fd, input_buffer, strlen(input_buffer));
            if (result != SSH_OK) {
                log_message(LOG_ERROR, "Failed to send data to server");
                return result;
            }
        }
    }
    
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
    
    printf("Simple SSH Client\n");
    printf("Connecting to %s:%d\n", server_host, server_port);
    
    // 初始化日志
    init_logger(LOG_DEBUG);
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 连接到服务器
    socket_fd = connect_to_server(server_host, server_port);
    if (socket_fd < 0) {
        fprintf(stderr, "Failed to connect to server\n");
        return 1;
    }
    
    log_message(LOG_INFO, "Connected to server %s:%d", server_host, server_port);
    printf("Connected to server %s:%d\n", server_host, server_port);
    
    // 进入主连接循环
    ssh_result_t result = handle_connection_data();
    
    // 清理资源
    if (socket_fd >= 0) {
        close(socket_fd);
    }
    
    if (result == SSH_OK) {
        printf("Disconnected from server\n");
        return 0;
    } else {
        fprintf(stderr, "Connection error: %s\n", ssh_error_string(result));
        return 1;
    }
}