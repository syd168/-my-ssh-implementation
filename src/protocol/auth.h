#ifndef AUTH_H
#define AUTH_H

#include "../common/common.h"
#include "ssh_protocol.h"
#include <stdint.h>

// 用户认证方法
#define AUTH_METHOD_NONE "none"
#define AUTH_METHOD_PASSWORD "password"
#define AUTH_METHOD_PUBLICKEY "publickey"

// SSH用户认证消息类型
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_SUCCESS 52
#define SSH_MSG_USERAUTH_BANNER 53

// 用户认证请求结构
typedef struct {
    char username[64];
    char service[32];
    char method[32];
    
    // 密码认证相关字段
    char password[128];
    
    // 公钥认证相关字段（简化实现）
    char public_key_algorithm[32];
    uint8_t *public_key;
    uint32_t public_key_len;
    uint8_t *signature;
    uint32_t signature_len;
} ssh_auth_request_t;

// 用户认证上下文
typedef struct {
    ssh_auth_request_t auth_request;
    int authenticated;
    char authenticated_method[32];
    int auth_attempts;
    int max_auth_attempts;
} ssh_auth_context_t;

// 用户信息结构
typedef struct {
    char username[64];
    char password[128];
    // 简化实现，实际项目中应该有更安全的密码存储方式
} user_info_t;

// 函数声明

/**
 * 初始化用户认证上下文
 * @param ctx 用户认证上下文
 * @return SSH操作结果
 */
ssh_result_t auth_init(ssh_auth_context_t *ctx);

/**
 * 创建用户认证请求消息
 * @param ctx 用户认证上下文
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH操作结果
 */
ssh_result_t auth_create_request(ssh_auth_context_t *ctx,
                                uint8_t *buffer,
                                uint32_t buffer_len,
                                uint32_t *message_len);

/**
 * 解析用户认证请求消息
 * @param ctx 用户认证上下文
 * @param data 消息数据
 * @param data_len 数据长度
 * @return SSH操作结果
 */
ssh_result_t auth_parse_request(ssh_auth_context_t *ctx,
                               const uint8_t *data,
                               uint32_t data_len);

/**
 * 验证用户凭据
 * @param ctx 用户认证上下文
 * @param user_db 用户数据库
 * @param user_count 用户数量
 * @return SSH操作结果
 */
ssh_result_t auth_verify_credentials(ssh_auth_context_t *ctx,
                                   const user_info_t *user_db,
                                   int user_count);

/**
 * 创建认证成功消息
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH操作结果
 */
ssh_result_t auth_create_success(uint8_t *buffer,
                                uint32_t buffer_len,
                                uint32_t *message_len);

/**
 * 创建认证失败消息
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH操作结果
 */
ssh_result_t auth_create_failure(uint8_t *buffer,
                                uint32_t buffer_len,
                                uint32_t *message_len);

/**
 * 清理用户认证上下文
 * @param ctx 用户认证上下文
 */
void auth_cleanup(ssh_auth_context_t *ctx);

// 辅助函数

/**
 * 验证用户名和密码
 * @param username 用户名
 * @param password 密码
 * @param user_db 用户数据库
 * @param user_count 用户数量
 * @return 1表示验证成功，0表示验证失败
 */
int verify_password(const char *username, 
                   const char *password, 
                   const user_info_t *user_db, 
                   int user_count);

#endif // AUTH_H