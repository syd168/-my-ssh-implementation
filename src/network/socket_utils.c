#include "socket_utils.h"

// 设置socket为非阻塞模式
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_message(LOG_ERROR, "Failed to get socket flags: %s", strerror(errno));
        return -1;
    }
    
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        log_message(LOG_ERROR, "Failed to set socket non-blocking: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

// 创建服务器socket
int create_server_socket(int port) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    // 创建socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log_message(LOG_ERROR, "Socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    // 设置socket选项，允许地址重用
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        log_message(LOG_ERROR, "Setsockopt failed: %s", strerror(errno));
        close(server_fd);
        return -1;
    }
    
    // 设置服务器地址
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    // 绑定socket到地址
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        log_message(LOG_ERROR, "Bind failed on port %d: %s", port, strerror(errno));
        close(server_fd);
        return -1;
    }
    
    // 开始监听
    if (listen(server_fd, MAX_CONNECTIONS) < 0) {
        log_message(LOG_ERROR, "Listen failed: %s", strerror(errno));
        close(server_fd);
        return -1;
    }
    
    log_message(LOG_INFO, "Server socket created and listening on port %d", port);
    return server_fd;
}

// 连接到服务器
int connect_to_server(const char *host, int port) {
    int client_fd;
    struct sockaddr_in serv_addr;
    
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_message(LOG_ERROR, "Socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    // 转换IP地址
    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        log_message(LOG_ERROR, "Invalid address/ Address not supported: %s", host);
        close(client_fd);
        return -1;
    }
    
    // 连接到服务器
    if (connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_message(LOG_ERROR, "Connection to %s:%d failed: %s", host, port, strerror(errno));
        close(client_fd);
        return -1;
    }
    
    log_message(LOG_INFO, "Connected to server %s:%d", host, port);
    return client_fd;
}

// 发送数据
ssh_result_t send_data(int fd, const char *data, size_t len) {
    size_t total_sent = 0;
    ssize_t sent;
    
    while (total_sent < len) {
        sent = send(fd, data + total_sent, len - total_sent, MSG_NOSIGNAL);
        
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 非阻塞模式下，socket暂时不可写
                if (wait_for_socket_ready(fd, 5, 1) <= 0) {
                    log_message(LOG_ERROR, "Send timeout or error");
                    return SSH_ERROR_TIMEOUT;
                }
                continue;
            } else if (errno == EPIPE || errno == ECONNRESET) {
                log_message(LOG_ERROR, "Connection lost during send: %s", strerror(errno));
                return SSH_ERROR_CONNECTION_LOST;
            } else {
                log_message(LOG_ERROR, "Send failed: %s", strerror(errno));
                return SSH_ERROR_NETWORK;
            }
        }
        
        if (sent == 0) {
            log_message(LOG_ERROR, "Connection closed by peer during send");
            return SSH_ERROR_CONNECTION_LOST;
        }
        
        total_sent += sent;
    }
    
    log_message(LOG_DEBUG, "Sent %zu bytes", total_sent);
    return SSH_OK;
}

// 接收数据
ssh_result_t receive_data(int fd, char *buffer, size_t buffer_size, size_t *received) {
    ssize_t bytes_received;
    
    *received = 0;
    
    bytes_received = recv(fd, buffer, buffer_size - 1, 0);
    
    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // 非阻塞模式下，没有数据可读
            return SSH_OK;
        } else if (errno == ECONNRESET) {
            log_message(LOG_ERROR, "Connection reset by peer");
            return SSH_ERROR_CONNECTION_LOST;
        } else {
            log_message(LOG_ERROR, "Receive failed: %s", strerror(errno));
            return SSH_ERROR_NETWORK;
        }
    }
    
    if (bytes_received == 0) {
        log_message(LOG_INFO, "Connection closed by peer");
        return SSH_ERROR_CONNECTION_LOST;
    }
    
    *received = bytes_received;
    buffer[bytes_received] = '\0'; // 添加字符串终止符
    
    log_message(LOG_DEBUG, "Received %zd bytes", bytes_received);
    return SSH_OK;
}

// 等待socket准备就绪
int wait_for_socket_ready(int fd, int timeout_sec, int for_write) {
    fd_set fds;
    struct timeval timeout;
    
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    
    if (for_write) {
        return select(fd + 1, NULL, &fds, NULL, &timeout);
    } else {
        return select(fd + 1, &fds, NULL, NULL, &timeout);
    }
}

// 关闭socket
void close_socket(int fd) {
    if (fd >= 0) {
        close(fd);
        log_message(LOG_DEBUG, "Socket %d closed", fd);
    }
}
