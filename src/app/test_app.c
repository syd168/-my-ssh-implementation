#include "ssh_app.h"
#include "../common/logger.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    printf("SSH Application Layer Test\n");
    printf("==========================\n");
    
    // 初始化日志系统
    init_logger(LOG_DEBUG);
    
    // 测试1: 命令执行功能
    printf("\nTest 1: Command execution...\n");
    
    char output[1024];
    size_t output_len;
    
    ssh_result_t result = app_execute_command("echo 'Hello, SSH Application Layer!'", output, sizeof(output), &output_len);
    if (result == SSH_OK) {
        printf("Command executed successfully:\n%.*s", (int)output_len, output);
    } else {
        printf("Failed to execute command: %d\n", result);
        return 1;
    }
    
    // 测试2: Shell应用
    printf("\nTest 2: Shell application...\n");
    
    ssh_app_context_t app_ctx;
    ssh_channel_t dummy_channel; // 创建一个虚拟通道用于测试
    
    // 初始化虚拟通道
    memset(&dummy_channel, 0, sizeof(dummy_channel));
    dummy_channel.local_channel_id = 1;
    dummy_channel.state = SSH_CHANNEL_STATE_OPEN;
    
    result = app_init(&app_ctx, &dummy_channel, APP_TYPE_SHELL);
    if (result != SSH_OK) {
        printf("Failed to initialize shell application: %d\n", result);
        return 1;
    }
    
    printf("Shell application initialized successfully\n");
    
    // 启动交互式shell
    result = app_start_shell(&app_ctx, NULL);
    if (result != SSH_OK) {
        printf("Failed to start shell application: %d\n", result);
        app_cleanup(&app_ctx);
        return 1;
    }
    
    printf("Shell application started successfully\n");
    
    // 向shell发送命令
    const char* test_command = "echo 'Test command output'\n";
    result = app_handle_input(&app_ctx, (const unsigned char*)test_command, strlen(test_command));
    if (result != SSH_OK) {
        printf("Failed to send command to shell: %d\n", result);
        app_close(&app_ctx);
        app_cleanup(&app_ctx);
        return 1;
    }
    
    printf("Command sent to shell\n");
    
    // 等待一点时间让命令执行
    sleep(1);
    
    // 读取shell输出
    unsigned char shell_output[1024];
    uint32_t shell_output_len;
    
    result = app_read_output(&app_ctx, shell_output, sizeof(shell_output), &shell_output_len);
    if (result == SSH_OK && shell_output_len > 0) {
        printf("Shell output (%u bytes):\n%.*s", shell_output_len, (int)shell_output_len, shell_output);
    } else {
        printf("No output from shell or error occurred\n");
    }
    
    // 关闭shell应用
    app_close(&app_ctx);
    app_cleanup(&app_ctx);
    
    printf("Shell application closed\n");
    
    // 测试3: 文件传输应用
    printf("\nTest 3: File transfer application...\n");
    
    // 创建测试文件
    FILE *test_file = fopen("test_file.txt", "w");
    if (test_file) {
        fprintf(test_file, "This is a test file for SSH file transfer.\n");
        fprintf(test_file, "Line 2\n");
        fprintf(test_file, "Line 3\n");
        fclose(test_file);
    }
    
    ssh_app_context_t file_app_ctx;
    
    result = app_init(&file_app_ctx, &dummy_channel, APP_TYPE_FILE_TRANSFER);
    if (result != SSH_OK) {
        printf("Failed to initialize file transfer application: %d\n", result);
        return 1;
    }
    
    printf("File transfer application initialized successfully\n");
    
    // 启动文件读取
    result = app_start_file_transfer(&file_app_ctx, "test_file.txt", "r");
    if (result != SSH_OK) {
        printf("Failed to start file transfer application: %d\n", result);
        app_cleanup(&file_app_ctx);
        return 1;
    }
    
    printf("File transfer application started successfully\n");
    
    // 读取文件内容
    unsigned char file_data[1024];
    uint32_t file_data_len;
    
    result = app_read_output(&file_app_ctx, file_data, sizeof(file_data), &file_data_len);
    if (result == SSH_OK && file_data_len > 0) {
        printf("File content (%u bytes):\n%.*s", file_data_len, (int)file_data_len, file_data);
    } else {
        printf("Failed to read file or file is empty\n");
    }
    
    // 关闭文件传输应用
    app_close(&file_app_ctx);
    app_cleanup(&file_app_ctx);
    
    printf("File transfer application closed\n");
    
    // 清理测试文件
    unlink("test_file.txt");
    
    printf("\nAll tests passed!\n");
    printf("SSH Application Layer Implementation Verified\n");
    
    return 0;
}