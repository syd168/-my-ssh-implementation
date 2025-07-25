#ifndef KEX_H
#define KEX_H

#include "../common/common.h"
#include "ssh_protocol.h"
#include "../crypto/dh.h"
#include <stdint.h>

// SSH密钥交换消息类型
#define SSH_MSG_KEXINIT    20
#define SSH_MSG_NEWKEYS    21
#define SSH_MSG_KEXDH_INIT 30
#define SSH_MSG_KEXDH_REPLY 31

// 算法名称长度限制
#define KEX_ALGORITHM_NAME_MAX 64
#define KEX_MAX_ALGORITHMS 10

// 支持的算法
extern const char* KEX_ALGORITHMS[];
extern const char* HOST_KEY_ALGORITHMS[];
extern const char* ENCRYPTION_ALGORITHMS[];  
extern const char* MAC_ALGORITHMS[];
extern const char* COMPRESSION_ALGORITHMS[];

// 密钥交换初始化消息结构
typedef struct {
    uint8_t cookie[16];                    // 随机cookie
    char kex_algorithms[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int kex_count;
    char server_host_key_algorithms[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int host_key_count;
    char encryption_algorithms_c2s[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int enc_c2s_count;
    char encryption_algorithms_s2c[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int enc_s2c_count;
    char mac_algorithms_c2s[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int mac_c2s_count;
    char mac_algorithms_s2c[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int mac_s2c_count;
    char compression_algorithms_c2s[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int comp_c2s_count;
    char compression_algorithms_s2c[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int comp_s2c_count;
    char languages_c2s[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int lang_c2s_count;
    char languages_s2c[KEX_MAX_ALGORITHMS][KEX_ALGORITHM_NAME_MAX];
    int lang_s2c_count;
    uint8_t first_kex_packet_follows;
    uint32_t reserved;
} ssh_kexinit_t;

// DH初始化消息结构
typedef struct {
    uint8_t *e;     // 客户端DH公钥
    uint32_t e_len;
} ssh_kexdh_init_t;

// DH回复消息结构
typedef struct {
    uint8_t *k_s;         // 服务器主机密钥
    uint32_t k_s_len;
    uint8_t *f;           // 服务器DH公钥
    uint32_t f_len;
    uint8_t *signature;   // 签名
    uint32_t sig_len;
} ssh_kexdh_reply_t;

// 密钥交换上下文
typedef struct {
    ssh_kexinit_t local_kexinit;    // 本地KEXINIT
    ssh_kexinit_t remote_kexinit;   // 远程KEXINIT
    dh_context_t dh_ctx;            // DH上下文
    ssh_connection_t conn;          // SSH连接上下文
    
    // 协商的算法
    char chosen_kex_algorithm[KEX_ALGORITHM_NAME_MAX];
    char chosen_server_host_key_algorithm[KEX_ALGORITHM_NAME_MAX];
    char chosen_encryption_c2s[KEX_ALGORITHM_NAME_MAX];
    char chosen_encryption_s2c[KEX_ALGORITHM_NAME_MAX];
    char chosen_mac_c2s[KEX_ALGORITHM_NAME_MAX];
    char chosen_mac_s2c[KEX_ALGORITHM_NAME_MAX];
    char chosen_compression_c2s[KEX_ALGORITHM_NAME_MAX];
    char chosen_compression_s2c[KEX_ALGORITHM_NAME_MAX];
    
    // 会话密钥和IV
    uint8_t session_key[32];
    uint32_t session_key_len;
    uint8_t shared_secret[DH_MAX_BYTES];
    uint32_t shared_secret_len;
    uint8_t iv_client_to_server[AES_IV_SIZE];
    uint8_t iv_server_to_client[AES_IV_SIZE];
    uint8_t encryption_key_client_to_server[AES_256_KEY_SIZE];
    uint8_t encryption_key_server_to_client[AES_256_KEY_SIZE];
    uint8_t hash[32];  // SHA-1哈希输出最大32字节
    uint32_t hash_len;
    
    // 会话ID
    uint8_t session_id[32];
    uint32_t session_id_len;
    
    // 状态
    int kexinit_sent;
    int kexinit_received;
    int kex_complete;
} ssh_kex_context_t;

// 密钥交换函数声明

/**
 * 初始化密钥交换上下文
 * @param ctx 密钥交换上下文
 * @param is_server 是否为服务器端
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_init(ssh_kex_context_t *ctx, int is_server);

/**
 * 创建KEXINIT消息
 * @param ctx 密钥交换上下文
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_create_kexinit(ssh_kex_context_t *ctx,
                               uint8_t *buffer,
                               uint32_t buffer_len,
                               uint32_t *message_len);

/**
 * 解析KEXINIT消息
 * @param ctx 密钥交换上下文
 * @param data 消息数据
 * @param data_len 数据长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_parse_kexinit(ssh_kex_context_t *ctx,
                              const uint8_t *data,
                              uint32_t data_len);

/**
 * 协商算法
 * @param ctx 密钥交换上下文
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_negotiate_algorithms(ssh_kex_context_t *ctx);

/**
 * 创建KEXDH_INIT消息（客户端）
 * @param ctx 密钥交换上下文
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_create_dh_init(ssh_kex_context_t *ctx,
                               uint8_t *buffer,
                               uint32_t buffer_len,
                               uint32_t *message_len);

/**
 * 解析KEXDH_INIT消息（服务器端）
 * @param ctx 密钥交换上下文
 * @param data 消息数据
 * @param data_len 数据长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_parse_dh_init(ssh_kex_context_t *ctx,
                              const uint8_t *data,
                              uint32_t data_len);

/**
 * 创建KEXDH_REPLY消息（服务器端）
 * @param ctx 密钥交换上下文
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_create_dh_reply(ssh_kex_context_t *ctx,
                                uint8_t *buffer,
                                uint32_t buffer_len,
                                uint32_t *message_len);

/**
 * 解析KEXDH_REPLY消息（客户端）
 * @param ctx 密钥交换上下文
 * @param data 消息数据
 * @param data_len 数据长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_parse_dh_reply(ssh_kex_context_t *ctx,
                               const uint8_t *data,
                               uint32_t data_len);

/**
 * 执行完整的密钥交换过程
 * @param socket_fd 套接字文件描述符
 * @param ctx 密钥交换上下文
 * @param local_version 本地版本信息
 * @param remote_version 远程版本信息
 * @return SSH_OK成功，其他失败
 */
ssh_result_t ssh_perform_key_exchange(int socket_fd,
                                     ssh_kex_context_t *ctx,
                                     const ssh_version_info_t *local_version,
                                     const ssh_version_info_t *remote_version);

/**
 * 创建KEXINIT消息
 * @param ctx 密钥交换上下文
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_create_kexinit(ssh_kex_context_t *ctx,
                               uint8_t *buffer,
                               uint32_t buffer_len,
                               uint32_t *message_len);

/**
 * 解析KEXINIT消息
 * @param ctx 密钥交换上下文
 * @param data 消息数据
 * @param data_len 数据长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_parse_kexinit(ssh_kex_context_t *ctx,
                              const uint8_t *data,
                              uint32_t data_len);

/**
 * 协商算法
 * @param ctx 密钥交换上下文
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_negotiate_algorithms(ssh_kex_context_t *ctx);

/**
 * 创建KEXDH_INIT消息（客户端）
 * @param ctx 密钥交换上下文
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_create_dh_init(ssh_kex_context_t *ctx,
                               uint8_t *buffer,
                               uint32_t buffer_len,
                               uint32_t *message_len);

/**
 * 解析KEXDH_INIT消息（服务器端）
 * @param ctx 密钥交换上下文
 * @param data 消息数据
 * @param data_len 数据长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_parse_dh_init(ssh_kex_context_t *ctx,
                              const uint8_t *data,
                              uint32_t data_len);

/**
 * 创建KEXDH_REPLY消息（服务器端）
 * @param ctx 密钥交换上下文
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_create_dh_reply(ssh_kex_context_t *ctx,
                                uint8_t *buffer,
                                uint32_t buffer_len,
                                uint32_t *message_len);

/**
 * 解析KEXDH_REPLY消息（客户端）
 * @param ctx 密钥交换上下文
 * @param data 消息数据
 * @param data_len 数据长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_parse_dh_reply(ssh_kex_context_t *ctx,
                               const uint8_t *data,
                               uint32_t data_len);

/**
 * 执行完整的密钥交换过程
 * @param socket_fd 套接字文件描述符
 * @param ctx 密钥交换上下文
 * @param local_version 本地版本信息
 * @param remote_version 远程版本信息
 * @return SSH_OK成功，其他失败
 */
ssh_result_t ssh_perform_key_exchange(int socket_fd,
                                     ssh_kex_context_t *ctx,
                                     const ssh_version_info_t *local_version,
                                     const ssh_version_info_t *remote_version);

/**
 * 完成密钥交换
 * @param ctx 密钥交换上下文
 * @return SSH_OK成功，其他失败
 */
ssh_result_t kex_finish(ssh_kex_context_t *ctx);

/**
 * 清理密钥交换上下文
 * @param ctx 密钥交换上下文
 */
void kex_cleanup(ssh_kex_context_t *ctx);

#endif // KEX_H