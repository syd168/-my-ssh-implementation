#include "common.h"

static log_level_t current_log_level = LOG_INFO;

// 设置日志级别
void set_log_level(log_level_t level) {
    current_log_level = level;
}

// 获取日志级别字符串
static const char* log_level_string(log_level_t level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
        default:        return "UNKNOWN";
    }
}

// 日志输出函数
void log_message(log_level_t level, const char *format, ...) {
    if (level < current_log_level) {
        return;
    }
    
    // 获取当前时间
    time_t now;
    struct tm *tm_info;
    char time_buffer[26];
    
    time(&now);
    tm_info = localtime(&now);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 输出时间和日志级别
    printf("[%s] [%s] ", time_buffer, log_level_string(level));
    
    // 输出格式化消息
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    printf("\n");
    fflush(stdout);
}

// 错误码转字符串
const char* ssh_error_string(ssh_result_t error) {
    switch (error) {
        case SSH_OK:                    return "Success";
        case SSH_ERROR_NETWORK:         return "Network error";
        case SSH_ERROR_MEMORY:          return "Memory allocation error";
        case SSH_ERROR_INVALID_PARAM:   return "Invalid parameter";
        case SSH_ERROR_TIMEOUT:         return "Operation timeout";
        case SSH_ERROR_CONNECTION_LOST: return "Connection lost";
        default:                        return "Unknown error";
    }
}
