#ifndef CHANNEL_H
#define CHANNEL_H

#include "../common/common.h"
#include "../crypto/aes.h"
#include "ssh_packet.h"
#include <stdint.h>

// SSH通道类型
#define SSH_CHANNEL_SESSION "session"
#define SSH_CHANNEL_DIRECT_TCP "direct-tcpip"
#define SSH_CHANNEL_FORWARDED_TCP "forwarded-tcpip"

// SSH通道状态
typedef enum {
    SSH_CHANNEL_STATE_OPEN = 0,
    SSH_CHANNEL_STATE_CLOSED = 1,
    SSH_CHANNEL_STATE_EOF_SENT = 2,
    SSH_CHANNEL_STATE_EOF_RECEIVED = 3
} ssh_channel_state_t;

// SSH通道消息类型
#define SSH_MSG_CHANNEL_OPEN           90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE   92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST  93
#define SSH_MSG_CHANNEL_DATA           94
#define SSH_MSG_CHANNEL_EXTENDED_DATA  95
#define SSH_MSG_CHANNEL_EOF            96
#define SSH_MSG_CHANNEL_CLOSE          97
#define SSH_MSG_CHANNEL_REQUEST        98
#define SSH_MSG_CHANNEL_SUCCESS        99
#define SSH_MSG_CHANNEL_FAILURE       100

// SSH通道打开失败原因代码
#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 1
#define SSH_OPEN_CONNECT_FAILED              2
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE        3
#define SSH_OPEN_RESOURCE_SHORTAGE           4

// SSH通道结构
typedef struct {
    uint32_t local_channel_id;     // 本地通道ID
    uint32_t remote_channel_id;    // 远程通道ID
    uint32_t local_window_size;    // 本地窗口大小
    uint32_t remote_window_size;   // 远程窗口大小
    uint32_t local_max_packet_size; // 本地最大包大小
    uint32_t remote_max_packet_size; // 远程最大包大小
    ssh_channel_state_t state;     // 通道状态
    char channel_type[32];         // 通道类型
    int socket_fd;                 // 套接字文件描述符
    
    // 加密上下文
    aes_context_t encrypt_ctx;     // 加密上下文
    aes_context_t decrypt_ctx;     // 解密上下文
    
    // HMAC上下文（简化实现）
    unsigned char send_hmac_key[64];  // 发送HMAC密钥
    unsigned char recv_hmac_key[64];  // 接收HMAC密钥
    uint32_t send_hmac_key_len;       // 发送HMAC密钥长度
    uint32_t recv_hmac_key_len;       // 接收HMAC密钥长度
    
    // 序列号
    uint32_t send_seq;             // 发送序列号
    uint32_t recv_seq;             // 接收序列号
    
    // 通道特定数据
    void *channel_data;            // 通道特定数据指针
} ssh_channel_t;

// SSH会话通道数据
typedef struct {
    char command[256];             // 执行的命令
    int want_reply;                // 是否需要回复
} ssh_session_channel_data_t;

// SSH TCP转发通道数据
typedef struct {
    char host[64];                 // 目标主机
    uint32_t port;                 // 目标端口
    char originator_ip[64];        // 发起者IP
    uint32_t originator_port;      // 发起者端口
} ssh_tcp_channel_data_t;

// 通道管理上下文
typedef struct {
    ssh_channel_t *channels;       // 通道数组
    uint32_t channel_count;        // 通道数量
    uint32_t max_channels;         // 最大通道数
    uint32_t next_channel_id;      // 下一个通道ID
} ssh_channel_manager_t;

// 函数声明

/**
 * 初始化通道管理器
 * @param manager 通道管理器
 * @param max_channels 最大通道数
 * @return SSH操作结果
 */
ssh_result_t channel_manager_init(ssh_channel_manager_t *manager, uint32_t max_channels);

/**
 * 创建新的SSH通道
 * @param manager 通道管理器
 * @param channel_type 通道类型
 * @param channel 输出通道指针
 * @return SSH操作结果
 */
ssh_result_t channel_create(ssh_channel_manager_t *manager, 
                           const char *channel_type, 
                           ssh_channel_t **channel);

/**
 * 打开SSH通道
 * @param channel SSH通道
 * @param socket_fd 套接字文件描述符
 * @return SSH操作结果
 */
ssh_result_t channel_open(ssh_channel_t *channel, int socket_fd);

/**
 * 关闭SSH通道
 * @param channel SSH通道
 * @return SSH操作结果
 */
ssh_result_t channel_close(ssh_channel_t *channel);

/**
 * 释放SSH通道
 * @param channel SSH通道
 * @return SSH操作结果
 */
ssh_result_t channel_free(ssh_channel_t *channel);

/**
 * 初始化通道加密
 * @param channel SSH通道
 * @param encryption_key 加密密钥
 * @param decryption_key 解密密钥
 * @param key_len 密钥长度
 * @param encryption_iv 加密IV
 * @param decryption_iv 解密IV
 * @return SSH操作结果
 */
ssh_result_t channel_init_encryption(ssh_channel_t *channel,
                                    const unsigned char *encryption_key,
                                    const unsigned char *decryption_key,
                                    uint32_t key_len,
                                    const unsigned char *encryption_iv,
                                    const unsigned char *decryption_iv);

/**
 * 初始化通道HMAC
 * @param channel SSH通道
 * @param send_hmac_key 发送HMAC密钥
 * @param send_hmac_key_len 发送HMAC密钥长度
 * @param recv_hmac_key 接收HMAC密钥
 * @param recv_hmac_key_len 接收HMAC密钥长度
 * @return SSH操作结果
 */
ssh_result_t channel_init_hmac(ssh_channel_t *channel,
                              const unsigned char *send_hmac_key,
                              uint32_t send_hmac_key_len,
                              const unsigned char *recv_hmac_key,
                              uint32_t recv_hmac_key_len);

/**
 * 加密并发送数据
 * @param channel SSH通道
 * @param data 数据
 * @param data_len 数据长度
 * @return SSH操作结果
 */
ssh_result_t channel_send_encrypted_data(ssh_channel_t *channel,
                                        const unsigned char *data,
                                        uint32_t data_len);

/**
 * 接收并解密数据
 * @param channel SSH通道
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param received_len 接收数据长度
 * @return SSH操作结果
 */
ssh_result_t channel_receive_decrypted_data(ssh_channel_t *channel,
                                           unsigned char *buffer,
                                           uint32_t buffer_len,
                                           uint32_t *received_len);

/**
 * 创建通道打开消息
 * @param channel SSH通道
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH操作结果
 */
ssh_result_t channel_create_open_message(ssh_channel_t *channel,
                                        uint8_t *buffer,
                                        uint32_t buffer_len,
                                        uint32_t *message_len);

/**
 * 解析通道打开消息
 * @param channel SSH通道
 * @param data 消息数据
 * @param data_len 数据长度
 * @return SSH操作结果
 */
ssh_result_t channel_parse_open_message(ssh_channel_t *channel,
                                       const uint8_t *data,
                                       uint32_t data_len);

/**
 * 创建通道数据消息
 * @param channel SSH通道
 * @param payload 数据载荷
 * @param payload_len 载荷长度
 * @param buffer 输出缓冲区
 * @param buffer_len 缓冲区长度
 * @param message_len 消息长度
 * @return SSH操作结果
 */
ssh_result_t channel_create_data_message(ssh_channel_t *channel,
                                        const unsigned char *payload,
                                        uint32_t payload_len,
                                        uint8_t *buffer,
                                        uint32_t buffer_len,
                                        uint32_t *message_len);

/**
 * 解析通道数据消息
 * @param channel SSH通道
 * @param data 消息数据
 * @param data_len 数据长度
 * @param payload 输出载荷
 * @param payload_len 载荷长度
 * @return SSH操作结果
 */
ssh_result_t channel_parse_data_message(ssh_channel_t *channel,
                                       const uint8_t *data,
                                       uint32_t data_len,
                                       unsigned char *payload,
                                       uint32_t *payload_len);

/**
 * 清理通道管理器
 * @param manager 通道管理器
 */
void channel_manager_cleanup(ssh_channel_manager_t *manager);

#endif // CHANNEL_H