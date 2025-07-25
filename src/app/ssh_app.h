#ifndef SSH_APP_H
#define SSH_APP_H

#include "../common/common.h"
#include "../protocol/channel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

// 应用类型
#define APP_TYPE_SHELL "shell"
#define APP_TYPE_EXEC "exec"
#define APP_TYPE_FILE_TRANSFER "file-transfer"

// 应用状态
typedef enum {
    APP_STATE_INITIALIZING = 0,
    APP_STATE_RUNNING = 1,
    APP_STATE_TERMINATED = 2
} app_state_t;

// Shell应用上下文
typedef struct {
    int pid;                    // 子进程ID
    int stdin_pipe[2];          // 父进程写入，子进程读取
    int stdout_pipe[2];         // 子进程写入，父进程读取
    int stderr_pipe[2];         // 子进程错误输出
    app_state_t state;          // 应用状态
    char command[256];          // 执行的命令
    int want_reply;             // 是否需要回复
} shell_app_context_t;

// 文件传输上下文
typedef struct {
    FILE *file;                 // 文件指针
    char filename[256];         // 文件名
    char mode[16];              // 文件操作模式 (r/w)
    size_t file_size;           // 文件大小
    size_t transferred;         // 已传输大小
    app_state_t state;          // 应用状态
} file_transfer_context_t;

// 应用上下文
typedef struct {
    char app_type[32];          // 应用类型
    union {
        shell_app_context_t shell_ctx;
        file_transfer_context_t file_ctx;
    } app_data;
    ssh_channel_t *channel;     // 关联的通道
    void *user_data;            // 用户数据
} ssh_app_context_t;

// 函数声明

/**
 * 初始化应用上下文
 * @param app_ctx 应用上下文
 * @param channel 关联的通道
 * @param app_type 应用类型
 * @return SSH操作结果
 */
ssh_result_t app_init(ssh_app_context_t *app_ctx, ssh_channel_t *channel, const char *app_type);

/**
 * 启动shell应用
 * @param app_ctx 应用上下文
 * @param command 要执行的命令（NULL表示交互式shell）
 * @return SSH操作结果
 */
ssh_result_t app_start_shell(ssh_app_context_t *app_ctx, const char *command);

/**
 * 启动文件传输应用
 * @param app_ctx 应用上下文
 * @param filename 文件名
 * @param mode 文件操作模式
 * @return SSH操作结果
 */
ssh_result_t app_start_file_transfer(ssh_app_context_t *app_ctx, const char *filename, const char *mode);

/**
 * 处理应用输入数据
 * @param app_ctx 应用上下文
 * @param data 输入数据
 * @param data_len 数据长度
 * @return SSH操作结果
 */
ssh_result_t app_handle_input(ssh_app_context_t *app_ctx, const unsigned char *data, uint32_t data_len);

/**
 * 读取应用输出数据
 * @param app_ctx 应用上下文
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param output_len 实际输出长度
 * @return SSH操作结果
 */
ssh_result_t app_read_output(ssh_app_context_t *app_ctx, unsigned char *buffer, uint32_t buffer_len, uint32_t *output_len);

/**
 * 关闭应用
 * @param app_ctx 应用上下文
 * @return SSH操作结果
 */
ssh_result_t app_close(ssh_app_context_t *app_ctx);

/**
 * 清理应用上下文
 * @param app_ctx 应用上下文
 */
void app_cleanup(ssh_app_context_t *app_ctx);

/**
 * 检查应用是否仍在运行
 * @param app_ctx 应用上下文
 * @return 1表示仍在运行，0表示已终止
 */
int app_is_running(ssh_app_context_t *app_ctx);

/**
 * 执行简单命令并返回结果
 * @param command 要执行的命令
 * @param output 输出缓冲区
 * @param output_len 输出长度
 * @param max_output_len 输出缓冲区最大长度
 * @return SSH操作结果
 */
ssh_result_t app_execute_command(const char *command, char *output, size_t max_output_len, size_t *output_len);

#endif // SSH_APP_H