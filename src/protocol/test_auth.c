#include "auth.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    printf("SSH Authentication Test\n");
    printf("=======================\n");
    
    // 初始化认证上下文
    ssh_auth_context_t ctx;
    ssh_result_t result = auth_init(&ctx);
    if (result != SSH_OK) {
        printf("Failed to initialize authentication context: %d\n", result);
        return 1;
    }
    
    printf("Authentication context initialized successfully\n");
    
    // 创建测试用户数据库
    user_info_t user_db[] = {
        {"testuser", "testpass"},
        {"admin", "admin123"},
        {"user", "password"}
    };
    int user_count = sizeof(user_db) / sizeof(user_db[0]);
    
    printf("Created test user database with %d users\n", user_count);
    
    // 测试1: 创建认证请求
    printf("\nTest 1: Creating authentication request...\n");
    
    strcpy(ctx.auth_request.username, "testuser");
    strcpy(ctx.auth_request.service, "ssh-connection");
    strcpy(ctx.auth_request.method, "password");
    strcpy(ctx.auth_request.password, "testpass");
    
    uint8_t request_buffer[1024];
    uint32_t request_len;
    result = auth_create_request(&ctx, request_buffer, sizeof(request_buffer), &request_len);
    if (result != SSH_OK) {
        printf("Failed to create authentication request: %d\n", result);
        auth_cleanup(&ctx);
        return 1;
    }
    
    printf("Authentication request created successfully: %u bytes\n", request_len);
    
    // 测试2: 解析认证请求
    printf("\nTest 2: Parsing authentication request...\n");
    
    ssh_auth_context_t parsed_ctx;
    result = auth_init(&parsed_ctx);
    if (result != SSH_OK) {
        printf("Failed to initialize parsed context: %d\n", result);
        auth_cleanup(&ctx);
        return 1;
    }
    
    result = auth_parse_request(&parsed_ctx, request_buffer, request_len);
    if (result != SSH_OK) {
        printf("Failed to parse authentication request: %d\n", result);
        auth_cleanup(&ctx);
        auth_cleanup(&parsed_ctx);
        return 1;
    }
    
    printf("Authentication request parsed successfully\n");
    printf("  Username: %s\n", parsed_ctx.auth_request.username);
    printf("  Service: %s\n", parsed_ctx.auth_request.service);
    printf("  Method: %s\n", parsed_ctx.auth_request.method);
    printf("  Password: %s\n", parsed_ctx.auth_request.password);
    
    // 测试3: 验证凭据
    printf("\nTest 3: Verifying credentials...\n");
    
    result = auth_verify_credentials(&parsed_ctx, user_db, user_count);
    if (result == SSH_OK) {
        printf("✓ Authentication successful\n");
    } else {
        printf("✗ Authentication failed: %d\n", result);
        auth_cleanup(&ctx);
        auth_cleanup(&parsed_ctx);
        return 1;
    }
    
    // 测试4: 创建认证成功消息
    printf("\nTest 4: Creating authentication success message...\n");
    
    uint8_t success_buffer[256];
    uint32_t success_len;
    result = auth_create_success(success_buffer, sizeof(success_buffer), &success_len);
    if (result != SSH_OK) {
        printf("Failed to create authentication success message: %d\n", result);
        auth_cleanup(&ctx);
        auth_cleanup(&parsed_ctx);
        return 1;
    }
    
    printf("Authentication success message created: %u bytes\n", success_len);
    printf("  Message type: %d\n", success_buffer[0]);
    
    // 测试5: 创建认证失败消息
    printf("\nTest 5: Creating authentication failure message...\n");
    
    uint8_t failure_buffer[256];
    uint32_t failure_len;
    result = auth_create_failure(failure_buffer, sizeof(failure_buffer), &failure_len);
    if (result != SSH_OK) {
        printf("Failed to create authentication failure message: %d\n", result);
        auth_cleanup(&ctx);
        auth_cleanup(&parsed_ctx);
        return 1;
    }
    
    printf("Authentication failure message created: %u bytes\n", failure_len);
    printf("  Message type: %d\n", failure_buffer[0]);
    
    // 测试6: 错误凭据验证
    printf("\nTest 6: Verifying with wrong credentials...\n");
    
    ssh_auth_context_t wrong_ctx;
    result = auth_init(&wrong_ctx);
    if (result != SSH_OK) {
        printf("Failed to initialize wrong context: %d\n", result);
        auth_cleanup(&ctx);
        auth_cleanup(&parsed_ctx);
        return 1;
    }
    
    strcpy(wrong_ctx.auth_request.username, "testuser");
    strcpy(wrong_ctx.auth_request.service, "ssh-connection");
    strcpy(wrong_ctx.auth_request.method, "password");
    strcpy(wrong_ctx.auth_request.password, "wrongpass");
    
    result = auth_verify_credentials(&wrong_ctx, user_db, user_count);
    if (result == SSH_ERROR_AUTH) {
        printf("✓ Authentication correctly failed with wrong password\n");
    } else {
        printf("✗ Authentication should have failed but didn't: %d\n", result);
        auth_cleanup(&ctx);
        auth_cleanup(&parsed_ctx);
        auth_cleanup(&wrong_ctx);
        return 1;
    }
    
    // 清理资源
    auth_cleanup(&ctx);
    auth_cleanup(&parsed_ctx);
    auth_cleanup(&wrong_ctx);
    
    printf("\nAll tests passed!\n");
    printf("SSH Authentication Implementation Verified\n");
    
    return 0;
}