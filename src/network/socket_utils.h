#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include "../common/common.h"

// Socket相关函数声明
int set_nonblocking(int fd);
int create_server_socket(int port);
int connect_to_server(const char *host, int port);
ssh_result_t send_data(int fd, const char *data, size_t len);
ssh_result_t receive_data(int fd, char *buffer, size_t buffer_size, size_t *received);
int wait_for_socket_ready(int fd, int timeout_sec, int for_write);
void close_socket(int fd);

#endif // SOCKET_UTILS_H
