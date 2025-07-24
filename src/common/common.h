#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <time.h>
#include <stdarg.h>

// 基本常量定义
#define MAX_BUFFER_SIZE 4096
#define MAX_MESSAGE_SIZE 1024
#define DEFAULT_PORT 2222
#define MAX_CONNECTIONS 10

// 错误码定义
typedef enum {
    SSH_OK = 0,
    SSH_ERROR_NETWORK = -1,
    SSH_ERROR_MEMORY = -2,
    SSH_ERROR_INVALID_PARAM = -3,
    SSH_ERROR_TIMEOUT = -4,
    SSH_ERROR_CONNECTION_LOST = -5
} ssh_result_t;

// 日志级别
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
} log_level_t;

// 连接状态
typedef enum {
    CONN_DISCONNECTED = 0,
    CONN_CONNECTING = 1,
    CONN_CONNECTED = 2,
    CONN_ERROR = 3
} connection_state_t;

// 函数声明
void log_message(log_level_t level, const char *format, ...);
const char* ssh_error_string(ssh_result_t error);
int set_nonblocking(int fd);
int create_server_socket(int port);
int accept_client_connection(int server_fd);
ssh_result_t send_data(int fd, const char *data, size_t len);
ssh_result_t receive_data(int fd, char *buffer, size_t buffer_size, size_t *received);

#endif // COMMON_H
