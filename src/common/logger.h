#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"

// 函数声明

/**
 * 设置日志级别
 * @param level 日志级别
 */
void set_log_level(log_level_t level);

/**
 * 日志输出函数
 * @param level 日志级别
 * @param format 格式化字符串
 * @param ... 可变参数
 */
void log_message(log_level_t level, const char *format, ...);

/**
 * 初始化日志系统
 * @param level 初始日志级别
 */
void init_logger(log_level_t level);

#endif // LOGGER_H