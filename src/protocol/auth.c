#include "auth.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// 初始化用户认证上下文
ssh_result_t auth_init(ssh_auth_context_t *ctx) {
    if (!ctx) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(ssh_auth_context_t));
    ctx->authenticated = 0;
    ctx->auth_attempts = 0;
    ctx->max_auth_attempts = 3; // 最多尝试3次
    
    log_message(LOG_DEBUG, "Authentication context initialized");
    return SSH_OK;
}

// 创建用户认证请求消息
ssh_result_t auth_create_request(ssh_auth_context_t *ctx,
                                uint8_t *buffer,
                                uint32_t buffer_len,
                                uint32_t *message_len) {
    if (!ctx || !buffer || !message_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 检查缓冲区大小
    uint32_t required_len = 1 + strlen(ctx->auth_request.username) + 
                           strlen(ctx->auth_request.service) + 
                           strlen(ctx->auth_request.method) + 
                           (strcmp(ctx->auth_request.method, AUTH_METHOD_PASSWORD) == 0 ? 
                            strlen(ctx->auth_request.password) : 0) + 10;
                           
    if (buffer_len < required_len) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    // 构造认证请求消息
    uint32_t offset = 0;
    
    // 消息类型
    buffer[offset++] = SSH_MSG_USERAUTH_REQUEST;
    
    // 用户名
    uint32_t username_len = strlen(ctx->auth_request.username);
    buffer[offset++] = (username_len >> 24) & 0xFF;
    buffer[offset++] = (username_len >> 16) & 0xFF;
    buffer[offset++] = (username_len >> 8) & 0xFF;
    buffer[offset++] = username_len & 0xFF;
    memcpy(buffer + offset, ctx->auth_request.username, username_len);
    offset += username_len;
    
    // 服务名
    uint32_t service_len = strlen(ctx->auth_request.service);
    buffer[offset++] = (service_len >> 24) & 0xFF;
    buffer[offset++] = (service_len >> 16) & 0xFF;
    buffer[offset++] = (service_len >> 8) & 0xFF;
    buffer[offset++] = service_len & 0xFF;
    memcpy(buffer + offset, ctx->auth_request.service, service_len);
    offset += service_len;
    
    // 认证方法
    uint32_t method_len = strlen(ctx->auth_request.method);
    buffer[offset++] = (method_len >> 24) & 0xFF;
    buffer[offset++] = (method_len >> 16) & 0xFF;
    buffer[offset++] = (method_len >> 8) & 0xFF;
    buffer[offset++] = method_len & 0xFF;
    memcpy(buffer + offset, ctx->auth_request.method, method_len);
    offset += method_len;
    
    // 如果是密码认证，添加密码
    if (strcmp(ctx->auth_request.method, AUTH_METHOD_PASSWORD) == 0) {
        // 是否需要密码（总是需要）
        buffer[offset++] = 0x01;
        
        // 密码
        uint32_t password_len = strlen(ctx->auth_request.password);
        buffer[offset++] = (password_len >> 24) & 0xFF;
        buffer[offset++] = (password_len >> 16) & 0xFF;
        buffer[offset++] = (password_len >> 8) & 0xFF;
        buffer[offset++] = password_len & 0xFF;
        memcpy(buffer + offset, ctx->auth_request.password, password_len);
        offset += password_len;
    }
    
    *message_len = offset;
    log_message(LOG_DEBUG, "Created authentication request for user: %s", ctx->auth_request.username);
    return SSH_OK;
}

// 解析用户认证请求消息
ssh_result_t auth_parse_request(ssh_auth_context_t *ctx,
                               const uint8_t *data,
                               uint32_t data_len) {
    if (!ctx || !data) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (data_len < 5) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t offset = 0;
    
    // 检查消息类型
    if (data[offset++] != SSH_MSG_USERAUTH_REQUEST) {
        return SSH_ERROR_PROTOCOL;
    }
    
    // 解析用户名
    if (offset + 4 > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t username_len = (data[offset] << 24) | (data[offset+1] << 16) | 
                           (data[offset+2] << 8) | data[offset+3];
    offset += 4;
    
    if (offset + username_len > data_len || username_len >= sizeof(ctx->auth_request.username)) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memcpy(ctx->auth_request.username, data + offset, username_len);
    ctx->auth_request.username[username_len] = '\0';
    offset += username_len;
    
    // 解析服务名
    if (offset + 4 > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t service_len = (data[offset] << 24) | (data[offset+1] << 16) | 
                          (data[offset+2] << 8) | data[offset+3];
    offset += 4;
    
    if (offset + service_len > data_len || service_len >= sizeof(ctx->auth_request.service)) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memcpy(ctx->auth_request.service, data + offset, service_len);
    ctx->auth_request.service[service_len] = '\0';
    offset += service_len;
    
    // 解析认证方法
    if (offset + 4 > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t method_len = (data[offset] << 24) | (data[offset+1] << 16) | 
                         (data[offset+2] << 8) | data[offset+3];
    offset += 4;
    
    if (offset + method_len > data_len || method_len >= sizeof(ctx->auth_request.method)) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memcpy(ctx->auth_request.method, data + offset, method_len);
    ctx->auth_request.method[method_len] = '\0';
    offset += method_len;
    
    // 如果是密码认证，解析密码
    if (strcmp(ctx->auth_request.method, AUTH_METHOD_PASSWORD) == 0) {
        // 跳过是否有密码字段
        if (offset + 1 > data_len) {
            return SSH_ERROR_INVALID_PARAM;
        }
        offset++;
        
        // 解析密码
        if (offset + 4 > data_len) {
            return SSH_ERROR_INVALID_PARAM;
        }
        
        uint32_t password_len = (data[offset] << 24) | (data[offset+1] << 16) | 
                               (data[offset+2] << 8) | data[offset+3];
        offset += 4;
        
        if (offset + password_len > data_len || password_len >= sizeof(ctx->auth_request.password)) {
            return SSH_ERROR_INVALID_PARAM;
        }
        
        memcpy(ctx->auth_request.password, data + offset, password_len);
        ctx->auth_request.password[password_len] = '\0';
        offset += password_len;
    }
    
    log_message(LOG_DEBUG, "Parsed authentication request for user: %s, method: %s", 
                ctx->auth_request.username, ctx->auth_request.method);
    return SSH_OK;
}

// 验证用户名和密码
int verify_password(const char *username, 
                   const char *password, 
                   const user_info_t *user_db, 
                   int user_count) {
    if (!username || !password || !user_db) {
        return 0;
    }
    
    for (int i = 0; i < user_count; i++) {
        if (strcmp(user_db[i].username, username) == 0 && 
            strcmp(user_db[i].password, password) == 0) {
            return 1;
        }
    }
    
    return 0;
}

// 验证用户凭据
ssh_result_t auth_verify_credentials(ssh_auth_context_t *ctx,
                                   const user_info_t *user_db,
                                   int user_count) {
    if (!ctx || !user_db) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 增加认证尝试次数
    ctx->auth_attempts++;
    
    // 检查是否超过最大尝试次数
    if (ctx->auth_attempts > ctx->max_auth_attempts) {
        log_message(LOG_WARN, "Too many authentication attempts for user: %s", 
                    ctx->auth_request.username);
        return SSH_ERROR_AUTH;
    }
    
    // 验证认证方法
    if (strcmp(ctx->auth_request.method, AUTH_METHOD_PASSWORD) != 0) {
        log_message(LOG_DEBUG, "Unsupported authentication method: %s", 
                    ctx->auth_request.method);
        return SSH_ERROR_AUTH;
    }
    
    // 验证凭据
    if (verify_password(ctx->auth_request.username, 
                       ctx->auth_request.password, 
                       user_db, 
                       user_count)) {
        ctx->authenticated = 1;
        strcpy(ctx->authenticated_method, ctx->auth_request.method);
        log_message(LOG_INFO, "User %s authenticated successfully", 
                    ctx->auth_request.username);
        return SSH_OK;
    } else {
        log_message(LOG_WARN, "Authentication failed for user: %s", 
                    ctx->auth_request.username);
        return SSH_ERROR_AUTH;
    }
}

// 创建认证成功消息
ssh_result_t auth_create_success(uint8_t *buffer,
                                uint32_t buffer_len,
                                uint32_t *message_len) {
    if (!buffer || !message_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (buffer_len < 1) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    buffer[0] = SSH_MSG_USERAUTH_SUCCESS;
    *message_len = 1;
    
    log_message(LOG_DEBUG, "Created authentication success message");
    return SSH_OK;
}

// 创建认证失败消息
ssh_result_t auth_create_failure(uint8_t *buffer,
                                uint32_t buffer_len,
                                uint32_t *message_len) {
    if (!buffer || !message_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 至少需要1字节消息类型 + 4字节方法数 + 1字节部分成功标志
    if (buffer_len < 6) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint32_t offset = 0;
    
    // 消息类型
    buffer[offset++] = SSH_MSG_USERAUTH_FAILURE;
    
    // 支持的方法数（我们只支持password）
    uint32_t method_count = 1;
    buffer[offset++] = (method_count >> 24) & 0xFF;
    buffer[offset++] = (method_count >> 16) & 0xFF;
    buffer[offset++] = (method_count >> 8) & 0xFF;
    buffer[offset++] = method_count & 0xFF;
    
    // 方法名长度
    uint32_t method_len = strlen(AUTH_METHOD_PASSWORD);
    buffer[offset++] = (method_len >> 24) & 0xFF;
    buffer[offset++] = (method_len >> 16) & 0xFF;
    buffer[offset++] = (method_len >> 8) & 0xFF;
    buffer[offset++] = method_len & 0xFF;
    
    // 检查缓冲区是否足够
    if (offset + method_len + 1 > buffer_len) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    // 方法名
    memcpy(buffer + offset, AUTH_METHOD_PASSWORD, method_len);
    offset += method_len;
    
    // 部分成功标志（不支持部分成功）
    buffer[offset++] = 0x00;
    
    *message_len = offset;
    
    log_message(LOG_DEBUG, "Created authentication failure message");
    return SSH_OK;
}

// 清理用户认证上下文
void auth_cleanup(ssh_auth_context_t *ctx) {
    if (ctx) {
        // 安全清零敏感信息
        volatile char *p;
        
        // 使用密码长度而不是指针大小来清零
        if (ctx->auth_request.password[0] != '\0') {
            size_t password_len = strlen(ctx->auth_request.password);
            p = (volatile char *)ctx->auth_request.password;
            for (size_t i = 0; i < password_len; i++) {
                p[i] = 0;
            }
        }
        
        memset(ctx, 0, sizeof(ssh_auth_context_t));
    }
}