#include "ssh_app.h"
#include "../common/logger.h"
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

// 初始化应用上下文
ssh_result_t app_init(ssh_app_context_t *app_ctx, ssh_channel_t *channel, const char *app_type) {
    if (!app_ctx || !channel || !app_type) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(app_ctx, 0, sizeof(ssh_app_context_t));
    app_ctx->channel = channel;
    strncpy(app_ctx->app_type, app_type, sizeof(app_ctx->app_type) - 1);
    app_ctx->app_type[sizeof(app_ctx->app_type) - 1] = '\0';
    
    log_message(LOG_DEBUG, "Application context initialized for type: %s", app_type);
    return SSH_OK;
}

// 启动shell应用
ssh_result_t app_start_shell(ssh_app_context_t *app_ctx, const char *command) {
    if (!app_ctx) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    shell_app_context_t *shell_ctx = &app_ctx->app_data.shell_ctx;
    
    // 创建管道
    if (pipe(shell_ctx->stdin_pipe) == -1) {
        log_message(LOG_ERROR, "Failed to create stdin pipe: %s", strerror(errno));
        return SSH_ERROR_NETWORK;
    }
    
    if (pipe(shell_ctx->stdout_pipe) == -1) {
        log_message(LOG_ERROR, "Failed to create stdout pipe: %s", strerror(errno));
        close(shell_ctx->stdin_pipe[0]);
        close(shell_ctx->stdin_pipe[1]);
        return SSH_ERROR_NETWORK;
    }
    
    if (pipe(shell_ctx->stderr_pipe) == -1) {
        log_message(LOG_ERROR, "Failed to create stderr pipe: %s", strerror(errno));
        close(shell_ctx->stdin_pipe[0]);
        close(shell_ctx->stdin_pipe[1]);
        close(shell_ctx->stdout_pipe[0]);
        close(shell_ctx->stdout_pipe[1]);
        return SSH_ERROR_NETWORK;
    }
    
    // 设置非阻塞模式
    fcntl(shell_ctx->stdout_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(shell_ctx->stderr_pipe[0], F_SETFL, O_NONBLOCK);
    
    // 保存命令
    if (command) {
        strncpy(shell_ctx->command, command, sizeof(shell_ctx->command) - 1);
        shell_ctx->command[sizeof(shell_ctx->command) - 1] = '\0';
    } else {
        shell_ctx->command[0] = '\0';
    }
    
    // 创建子进程
    shell_ctx->pid = fork();
    if (shell_ctx->pid == -1) {
        log_message(LOG_ERROR, "Failed to fork process: %s", strerror(errno));
        close(shell_ctx->stdin_pipe[0]);
        close(shell_ctx->stdin_pipe[1]);
        close(shell_ctx->stdout_pipe[0]);
        close(shell_ctx->stdout_pipe[1]);
        close(shell_ctx->stderr_pipe[0]);
        close(shell_ctx->stderr_pipe[1]);
        return SSH_ERROR_NETWORK;
    }
    
    if (shell_ctx->pid == 0) {
        // 子进程
        // 关闭不需要的管道端
        close(shell_ctx->stdin_pipe[1]);   // 关闭写端
        close(shell_ctx->stdout_pipe[0]);  // 关闭读端
        close(shell_ctx->stderr_pipe[0]);  // 关闭读端
        
        // 重定向标准输入/输出/错误
        dup2(shell_ctx->stdin_pipe[0], STDIN_FILENO);
        dup2(shell_ctx->stdout_pipe[1], STDOUT_FILENO);
        dup2(shell_ctx->stderr_pipe[1], STDERR_FILENO);
        
        // 关闭原始管道文件描述符
        close(shell_ctx->stdin_pipe[0]);
        close(shell_ctx->stdout_pipe[1]);
        close(shell_ctx->stderr_pipe[1]);
        
        // 执行命令或shell
        if (shell_ctx->command[0] != '\0') {
            // 执行特定命令
            execl("/bin/sh", "sh", "-c", shell_ctx->command, (char *)NULL);
        } else {
            // 启动交互式shell
            execl("/bin/sh", "sh", (char *)NULL);
        }
        
        // 如果execl失败
        perror("execl failed");
        _exit(1);
    } else {
        // 父进程
        // 关闭不需要的管道端
        close(shell_ctx->stdin_pipe[0]);   // 关闭读端
        close(shell_ctx->stdout_pipe[1]);  // 关闭写端
        close(shell_ctx->stderr_pipe[1]);  // 关闭写端
        
        shell_ctx->state = APP_STATE_RUNNING;
        log_message(LOG_INFO, "Shell application started with PID: %d", shell_ctx->pid);
        return SSH_OK;
    }
}

// 启动文件传输应用
ssh_result_t app_start_file_transfer(ssh_app_context_t *app_ctx, const char *filename, const char *mode) {
    if (!app_ctx || !filename || !mode) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    file_transfer_context_t *file_ctx = &app_ctx->app_data.file_ctx;
    
    // 保存文件名和模式
    strncpy(file_ctx->filename, filename, sizeof(file_ctx->filename) - 1);
    file_ctx->filename[sizeof(file_ctx->filename) - 1] = '\0';
    
    strncpy(file_ctx->mode, mode, sizeof(file_ctx->mode) - 1);
    file_ctx->mode[sizeof(file_ctx->mode) - 1] = '\0';
    
    // 打开文件
    file_ctx->file = fopen(filename, mode);
    if (!file_ctx->file) {
        log_message(LOG_ERROR, "Failed to open file %s with mode %s: %s", filename, mode, strerror(errno));
        return SSH_ERROR_NETWORK;
    }
    
    // 获取文件大小
    if (strcmp(mode, "r") == 0 || strcmp(mode, "rb") == 0) {
        fseek(file_ctx->file, 0, SEEK_END);
        file_ctx->file_size = ftell(file_ctx->file);
        fseek(file_ctx->file, 0, SEEK_SET);
    }
    
    file_ctx->transferred = 0;
    file_ctx->state = APP_STATE_RUNNING;
    
    log_message(LOG_INFO, "File transfer application started for file: %s", filename);
    return SSH_OK;
}

// 处理应用输入数据
ssh_result_t app_handle_input(ssh_app_context_t *app_ctx, const unsigned char *data, uint32_t data_len) {
    if (!app_ctx || !data) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (strcmp(app_ctx->app_type, APP_TYPE_SHELL) == 0) {
        // 处理shell应用输入
        shell_app_context_t *shell_ctx = &app_ctx->app_data.shell_ctx;
        
        if (shell_ctx->state != APP_STATE_RUNNING) {
            log_message(LOG_WARN, "Shell application is not running");
            return SSH_ERROR_INVALID_PARAM;
        }
        
        // 将数据写入shell的stdin
        ssize_t written = write(shell_ctx->stdin_pipe[1], data, data_len);
        if (written == -1) {
            log_message(LOG_ERROR, "Failed to write to shell stdin: %s", strerror(errno));
            return SSH_ERROR_NETWORK;
        }
        
        log_message(LOG_DEBUG, "Wrote %zd bytes to shell stdin", written);
        return SSH_OK;
    } else if (strcmp(app_ctx->app_type, APP_TYPE_FILE_TRANSFER) == 0) {
        // 处理文件传输输入
        file_transfer_context_t *file_ctx = &app_ctx->app_data.file_ctx;
        
        if (file_ctx->state != APP_STATE_RUNNING) {
            log_message(LOG_WARN, "File transfer application is not running");
            return SSH_ERROR_INVALID_PARAM;
        }
        
        // 检查是否是写模式
        if (strcmp(file_ctx->mode, "w") != 0 && strcmp(file_ctx->mode, "wb") != 0) {
            log_message(LOG_WARN, "File is not opened in write mode");
            return SSH_ERROR_INVALID_PARAM;
        }
        
        // 写入文件
        size_t written = fwrite(data, 1, data_len, file_ctx->file);
        if (written != data_len) {
            log_message(LOG_ERROR, "Failed to write to file: %s", strerror(errno));
            return SSH_ERROR_NETWORK;
        }
        
        file_ctx->transferred += written;
        log_message(LOG_DEBUG, "Wrote %zu bytes to file", written);
        return SSH_OK;
    }
    
    log_message(LOG_WARN, "Unsupported application type: %s", app_ctx->app_type);
    return SSH_ERROR_INVALID_PARAM;
}

// 读取应用输出数据
ssh_result_t app_read_output(ssh_app_context_t *app_ctx, unsigned char *buffer, uint32_t buffer_len, uint32_t *output_len) {
    if (!app_ctx || !buffer || !output_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    *output_len = 0;
    
    if (strcmp(app_ctx->app_type, APP_TYPE_SHELL) == 0) {
        // 读取shell应用输出
        shell_app_context_t *shell_ctx = &app_ctx->app_data.shell_ctx;
        
        if (shell_ctx->state != APP_STATE_RUNNING) {
            log_message(LOG_DEBUG, "Shell application is not running");
            return SSH_OK; // 不是错误，只是没有输出
        }
        
        // 检查stdout是否有数据
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(shell_ctx->stdout_pipe[0], &read_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        
        int result = select(shell_ctx->stdout_pipe[0] + 1, &read_fds, NULL, NULL, &timeout);
        if (result > 0 && FD_ISSET(shell_ctx->stdout_pipe[0], &read_fds)) {
            // 读取stdout数据
            ssize_t bytes_read = read(shell_ctx->stdout_pipe[0], buffer, buffer_len);
            if (bytes_read > 0) {
                *output_len = bytes_read;
                log_message(LOG_DEBUG, "Read %zd bytes from shell stdout", bytes_read);
            } else if (bytes_read == 0) {
                // EOF
                log_message(LOG_DEBUG, "EOF reached on shell stdout");
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_message(LOG_ERROR, "Error reading from shell stdout: %s", strerror(errno));
                return SSH_ERROR_NETWORK;
            }
        }
        
        // 检查stderr是否有数据
        FD_ZERO(&read_fds);
        FD_SET(shell_ctx->stderr_pipe[0], &read_fds);
        
        result = select(shell_ctx->stderr_pipe[0] + 1, &read_fds, NULL, NULL, &timeout);
        if (result > 0 && FD_ISSET(shell_ctx->stderr_pipe[0], &read_fds)) {
            // 我们将stderr数据也读取到缓冲区中（在实际SSH实现中，stderr应该单独处理）
            if (*output_len < buffer_len) {
                ssize_t bytes_read = read(shell_ctx->stderr_pipe[0], 
                                         buffer + *output_len, 
                                         buffer_len - *output_len);
                if (bytes_read > 0) {
                    *output_len += bytes_read;
                    log_message(LOG_DEBUG, "Read %zd bytes from shell stderr", bytes_read);
                } else if (bytes_read == 0) {
                    // EOF
                    log_message(LOG_DEBUG, "EOF reached on shell stderr");
                } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    log_message(LOG_ERROR, "Error reading from shell stderr: %s", strerror(errno));
                }
            }
        }
        
        return SSH_OK;
    } else if (strcmp(app_ctx->app_type, APP_TYPE_FILE_TRANSFER) == 0) {
        // 读取文件传输输出
        file_transfer_context_t *file_ctx = &app_ctx->app_data.file_ctx;
        
        if (file_ctx->state != APP_STATE_RUNNING) {
            log_message(LOG_DEBUG, "File transfer application is not running");
            return SSH_OK; // 不是错误，只是没有输出
        }
        
        // 检查是否是读模式
        if (strcmp(file_ctx->mode, "r") != 0 && strcmp(file_ctx->mode, "rb") != 0) {
            log_message(LOG_WARN, "File is not opened in read mode");
            return SSH_OK;
        }
        
        // 读取文件数据
        size_t bytes_read = fread(buffer, 1, buffer_len, file_ctx->file);
        if (bytes_read > 0) {
            *output_len = bytes_read;
            file_ctx->transferred += bytes_read;
            log_message(LOG_DEBUG, "Read %zu bytes from file", bytes_read);
        } else if (feof(file_ctx->file)) {
            // 文件结束
            log_message(LOG_DEBUG, "EOF reached on file");
        } else if (ferror(file_ctx->file)) {
            log_message(LOG_ERROR, "Error reading from file");
            return SSH_ERROR_NETWORK;
        }
        
        return SSH_OK;
    }
    
    log_message(LOG_WARN, "Unsupported application type: %s", app_ctx->app_type);
    return SSH_ERROR_INVALID_PARAM;
}

// 关闭应用
ssh_result_t app_close(ssh_app_context_t *app_ctx) {
    if (!app_ctx) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (strcmp(app_ctx->app_type, APP_TYPE_SHELL) == 0) {
        shell_app_context_t *shell_ctx = &app_ctx->app_data.shell_ctx;
        
        if (shell_ctx->state == APP_STATE_RUNNING) {
            // 关闭管道
            if (shell_ctx->stdin_pipe[1] != -1) {
                close(shell_ctx->stdin_pipe[1]);
                shell_ctx->stdin_pipe[1] = -1;
            }
            
            if (shell_ctx->stdout_pipe[0] != -1) {
                close(shell_ctx->stdout_pipe[0]);
                shell_ctx->stdout_pipe[0] = -1;
            }
            
            if (shell_ctx->stderr_pipe[0] != -1) {
                close(shell_ctx->stderr_pipe[0]);
                shell_ctx->stderr_pipe[0] = -1;
            }
            
            // 等待子进程结束
            int status;
            if (shell_ctx->pid > 0) {
                waitpid(shell_ctx->pid, &status, WNOHANG);
            }
            
            shell_ctx->state = APP_STATE_TERMINATED;
            log_message(LOG_INFO, "Shell application closed");
        }
        
        return SSH_OK;
    } else if (strcmp(app_ctx->app_type, APP_TYPE_FILE_TRANSFER) == 0) {
        file_transfer_context_t *file_ctx = &app_ctx->app_data.file_ctx;
        
        if (file_ctx->state == APP_STATE_RUNNING) {
            if (file_ctx->file) {
                fclose(file_ctx->file);
                file_ctx->file = NULL;
            }
            
            file_ctx->state = APP_STATE_TERMINATED;
            log_message(LOG_INFO, "File transfer application closed");
        }
        
        return SSH_OK;
    }
    
    log_message(LOG_WARN, "Unsupported application type: %s", app_ctx->app_type);
    return SSH_ERROR_INVALID_PARAM;
}

// 清理应用上下文
void app_cleanup(ssh_app_context_t *app_ctx) {
    if (app_ctx) {
        // 关闭应用
        app_close(app_ctx);
        
        // 清理资源
        memset(app_ctx, 0, sizeof(ssh_app_context_t));
        
        log_message(LOG_DEBUG, "Application context cleaned up");
    }
}

// 检查应用是否仍在运行
int app_is_running(ssh_app_context_t *app_ctx) {
    if (!app_ctx) {
        return 0;
    }
    
    if (strcmp(app_ctx->app_type, APP_TYPE_SHELL) == 0) {
        shell_app_context_t *shell_ctx = &app_ctx->app_data.shell_ctx;
        return (shell_ctx->state == APP_STATE_RUNNING);
    } else if (strcmp(app_ctx->app_type, APP_TYPE_FILE_TRANSFER) == 0) {
        file_transfer_context_t *file_ctx = &app_ctx->app_data.file_ctx;
        return (file_ctx->state == APP_STATE_RUNNING);
    }
    
    return 0;
}

// 执行简单命令并返回结果
ssh_result_t app_execute_command(const char *command, char *output, size_t max_output_len, size_t *output_len) {
    if (!command || !output || !output_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    *output_len = 0;
    
    // 使用popen执行命令
    FILE *fp = popen(command, "r");
    if (!fp) {
        log_message(LOG_ERROR, "Failed to execute command: %s", strerror(errno));
        return SSH_ERROR_NETWORK;
    }
    
    // 读取命令输出
    size_t total_read = 0;
    size_t bytes_read;
    
    while (total_read < max_output_len - 1) {
        bytes_read = fread(output + total_read, 1, max_output_len - total_read - 1, fp);
        if (bytes_read == 0) {
            break;
        }
        total_read += bytes_read;
    }
    
    // 确保字符串以null结尾
    output[total_read] = '\0';
    *output_len = total_read;
    
    // 关闭popen
    int result = pclose(fp);
    if (result == -1) {
        log_message(LOG_ERROR, "Failed to close command pipe: %s", strerror(errno));
        return SSH_ERROR_NETWORK;
    }
    
    log_message(LOG_DEBUG, "Executed command '%s', returned %zu bytes", command, *output_len);
    return SSH_OK;
}