#ifndef SSH_PACKET_H
#define SSH_PACKET_H

#include "../common/common.h"
#include <stdint.h>

// SSH数据包最大大小
#define SSH_PACKET_MAX_SIZE 65536

// SSH消息类型
#define SSH_MSG_DISCONNECT          1
#define SSH_MSG_IGNORE              2
#define SSH_MSG_UNIMPLEMENTED       3
#define SSH_MSG_DEBUG               4
#define SSH_MSG_SERVICE_REQUEST     5
#define SSH_MSG_SERVICE_ACCEPT      6
#define SSH_MSG_KEXINIT            20
#define SSH_MSG_NEWKEYS            21
#define SSH_MSG_KEXDH_INIT         30
#define SSH_MSG_KEXDH_REPLY        31
#define SSH_MSG_USERAUTH_REQUEST   50
#define SSH_MSG_USERAUTH_FAILURE   51
#define SSH_MSG_USERAUTH_SUCCESS   52
#define SSH_MSG_USERAUTH_BANNER    53
#define SSH_MSG_GLOBAL_REQUEST     80
#define SSH_MSG_REQUEST_SUCCESS    81
#define SSH_MSG_REQUEST_FAILURE    82
#define SSH_MSG_CHANNEL_OPEN       90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE 92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA       94
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95
#define SSH_MSG_CHANNEL_EOF        96
#define SSH_MSG_CHANNEL_CLOSE      97
#define SSH_MSG_CHANNEL_REQUEST    98
#define SSH_MSG_CHANNEL_SUCCESS    99
#define SSH_MSG_CHANNEL_FAILURE   100

// SSH断开连接原因代码
#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT          1
#define SSH_DISCONNECT_PROTOCOL_ERROR                       2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED                  3
#define SSH_DISCONNECT_RESERVED                             4
#define SSH_DISCONNECT_MAC_ERROR                            5
#define SSH_DISCONNECT_COMPRESSION_ERROR                    6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED       8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE              9
#define SSH_DISCONNECT_CONNECTION_LOST                     10
#define SSH_DISCONNECT_BY_APPLICATION                      11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS                12
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER              13
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE      14
#define SSH_DISCONNECT_ILLEGAL_USER_NAME                   15

// SSH数据包结构
typedef struct {
    uint32_t packet_length;     // 数据包长度（网络字节序）
    uint8_t padding_length;     // 填充长度
    uint8_t *payload;           // 有效载荷
    uint32_t payload_length;    // 有效载荷长度
    uint8_t *padding;           // 随机填充
    uint8_t *mac;              // 消息认证码（如果有）
    uint32_t mac_length;       // MAC长度
} ssh_packet_t;

// SSH数据包上下文
typedef struct {
    uint32_t sequence_number;   // 序列号
    uint32_t max_packet_size;   // 最大数据包大小
    int mac_enabled;           // 是否启用MAC
    char mac_algorithm[32];    // MAC算法
    uint8_t *mac_key;          // MAC密钥
    uint32_t mac_key_length;   // MAC密钥长度
} ssh_packet_context_t;

// 函数声明

/**
 * 初始化SSH数据包上下文
 * @param ctx 数据包上下文
 * @return SSH操作结果
 */
ssh_result_t packet_init_context(ssh_packet_context_t *ctx);

/**
 * 创建SSH数据包
 * @param ctx 数据包上下文
 * @param payload 有效载荷数据
 * @param payload_length 有效载荷长度
 * @param packet 输出数据包
 * @return SSH操作结果
 */
ssh_result_t packet_create(ssh_packet_context_t *ctx,
                          const uint8_t *payload,
                          uint32_t payload_length,
                          ssh_packet_t *packet);

/**
 * 解析SSH数据包
 * @param ctx 数据包上下文
 * @param data 数据
 * @param data_length 数据长度
 * @param packet 输出数据包
 * @return SSH操作结果
 */
ssh_result_t packet_parse(ssh_packet_context_t *ctx,
                         const uint8_t *data,
                         uint32_t data_length,
                         ssh_packet_t *packet);

/**
 * 序列化SSH数据包
 * @param ctx 数据包上下文
 * @param packet 数据包
 * @param buffer 输出缓冲区
 * @param buffer_length 缓冲区长度
 * @param written 输出写入字节数
 * @return SSH操作结果
 */
ssh_result_t packet_serialize(ssh_packet_context_t *ctx,
                             const ssh_packet_t *packet,
                             uint8_t *buffer,
                             uint32_t buffer_length,
                             uint32_t *written);

/**
 * 释放SSH数据包资源
 * @param packet 数据包
 */
void packet_free(ssh_packet_t *packet);

/**
 * 清理SSH数据包上下文
 * @param ctx 数据包上下文
 */
void packet_cleanup_context(ssh_packet_context_t *ctx);

// 辅助函数

/**
 * 计算数据包填充长度
 * @param payload_length 有效载荷长度
 * @param block_size 块大小
 * @return 填充长度
 */
uint8_t packet_calculate_padding(uint32_t payload_length, uint8_t block_size);

/**
 * 生成随机填充
 * @param padding 填充缓冲区
 * @param padding_length 填充长度
 * @return SSH操作结果
 */
ssh_result_t packet_generate_padding(uint8_t *padding, uint8_t padding_length);

/**
 * 获取消息类型字符串描述
 * @param message_type 消息类型
 * @return 消息类型描述
 */
const char* packet_message_type_string(uint8_t message_type);

#endif // SSH_PACKET_H