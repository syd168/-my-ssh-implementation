#include "ssh_packet.h"
#include "../crypto/aes.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

// 初始化SSH数据包上下文
ssh_result_t packet_init_context(ssh_packet_context_t *ctx) {
    if (!ctx) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(ssh_packet_context_t));
    ctx->sequence_number = 0;
    ctx->max_packet_size = SSH_PACKET_MAX_SIZE;
    ctx->mac_enabled = 0;
    strcpy(ctx->mac_algorithm, "none");
    ctx->mac_key = NULL;
    ctx->mac_key_length = 0;
    
    log_message(LOG_DEBUG, "SSH packet context initialized");
    return SSH_OK;
}

// 计算数据包填充长度
uint8_t packet_calculate_padding(uint32_t payload_length, uint8_t block_size) {
    // 填充需要确保整个数据包长度是块大小的整数倍
    // 数据包结构: 4字节长度 + 1字节填充长度 + 有效载荷 + 填充
    uint32_t total_length = 4 + 1 + payload_length;
    uint8_t padding = block_size - (total_length % block_size);
    
    // 填充长度至少为4字节，最多为255字节
    if (padding < 4) {
        padding += block_size;
    }
    
    return padding;
}

// 生成随机填充
ssh_result_t packet_generate_padding(uint8_t *padding, uint8_t padding_length) {
    if (!padding || padding_length == 0) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        log_message(LOG_ERROR, "Failed to open /dev/urandom for padding generation");
        return SSH_ERROR_CRYPTO;
    }
    
    ssize_t bytes_read = read(fd, padding, padding_length);
    close(fd);
    
    if (bytes_read != padding_length) {
        log_message(LOG_ERROR, "Failed to read enough random bytes for padding");
        return SSH_ERROR_CRYPTO;
    }
    
    return SSH_OK;
}

// 创建SSH数据包
ssh_result_t packet_create(ssh_packet_context_t *ctx,
                          const uint8_t *payload,
                          uint32_t payload_length,
                          ssh_packet_t *packet) {
    if (!ctx || !payload || !packet) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (payload_length > ctx->max_packet_size) {
        log_message(LOG_ERROR, "Payload length exceeds maximum packet size");
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(packet, 0, sizeof(ssh_packet_t));
    
    // 计算填充长度（使用AES块大小）
    packet->padding_length = packet_calculate_padding(payload_length, AES_BLOCK_SIZE);
    
    // 设置有效载荷
    packet->payload_length = payload_length;
    packet->payload = malloc(payload_length);
    if (!packet->payload) {
        log_message(LOG_ERROR, "Failed to allocate memory for payload");
        return SSH_ERROR_MEMORY;
    }
    memcpy(packet->payload, payload, payload_length);
    
    // 生成随机填充
    packet->padding = malloc(packet->padding_length);
    if (!packet->padding) {
        log_message(LOG_ERROR, "Failed to allocate memory for padding");
        free(packet->payload);
        packet->payload = NULL;
        return SSH_ERROR_MEMORY;
    }
    
    ssh_result_t result = packet_generate_padding(packet->padding, packet->padding_length);
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to generate padding");
        free(packet->payload);
        free(packet->padding);
        packet->payload = NULL;
        packet->padding = NULL;
        return result;
    }
    
    // 计算数据包长度（不包括长度字段本身）
    packet->packet_length = 1 + payload_length + packet->padding_length;
    
    log_message(LOG_DEBUG, "Created SSH packet: length=%u, payload_length=%u, padding_length=%u",
                packet->packet_length, packet->payload_length, packet->padding_length);
    
    return SSH_OK;
}

// 解析SSH数据包
ssh_result_t packet_parse(ssh_packet_context_t *ctx,
                         const uint8_t *data,
                         uint32_t data_length,
                         ssh_packet_t *packet) {
    if (!ctx || !data || !packet) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (data_length < 5) { // 至少需要长度字段(4) + 填充长度字段(1)
        log_message(LOG_ERROR, "Data too short to be a valid SSH packet");
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(packet, 0, sizeof(ssh_packet_t));
    
    // 解析数据包长度
    packet->packet_length = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    
    if (packet->packet_length > ctx->max_packet_size) {
        log_message(LOG_ERROR, "Packet length exceeds maximum allowed size");
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (packet->packet_length + 4 > data_length) {
        log_message(LOG_ERROR, "Packet length mismatch with available data");
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 解析填充长度
    packet->padding_length = data[4];
    
    // 验证填充长度
    if (packet->padding_length < 4 || packet->padding_length > packet->packet_length - 1) {
        log_message(LOG_ERROR, "Invalid padding length");
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 计算有效载荷长度
    packet->payload_length = packet->packet_length - 1 - packet->padding_length;
    
    // 解析有效载荷
    if (packet->payload_length > 0) {
        packet->payload = malloc(packet->payload_length);
        if (!packet->payload) {
            log_message(LOG_ERROR, "Failed to allocate memory for payload");
            return SSH_ERROR_MEMORY;
        }
        memcpy(packet->payload, data + 5, packet->payload_length);
    }
    
    // 解析填充
    if (packet->padding_length > 0) {
        packet->padding = malloc(packet->padding_length);
        if (!packet->padding) {
            log_message(LOG_ERROR, "Failed to allocate memory for padding");
            if (packet->payload) {
                free(packet->payload);
                packet->payload = NULL;
            }
            return SSH_ERROR_MEMORY;
        }
        memcpy(packet->padding, data + 5 + packet->payload_length, packet->padding_length);
    }
    
    log_message(LOG_DEBUG, "Parsed SSH packet: length=%u, payload_length=%u, padding_length=%u",
                packet->packet_length, packet->payload_length, packet->padding_length);
    
    return SSH_OK;
}

// 序列化SSH数据包
ssh_result_t packet_serialize(ssh_packet_context_t *ctx,
                             const ssh_packet_t *packet,
                             uint8_t *buffer,
                             uint32_t buffer_length,
                             uint32_t *written) {
    if (!ctx || !packet || !buffer || !written) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 计算所需缓冲区大小
    uint32_t required_size = 4 + packet->packet_length; // 4字节长度字段 + 数据包内容
    
    if (buffer_length < required_size) {
        log_message(LOG_ERROR, "Buffer too small for packet serialization");
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint32_t offset = 0;
    
    // 序列化数据包长度
    buffer[offset++] = (packet->packet_length >> 24) & 0xFF;
    buffer[offset++] = (packet->packet_length >> 16) & 0xFF;
    buffer[offset++] = (packet->packet_length >> 8) & 0xFF;
    buffer[offset++] = packet->packet_length & 0xFF;
    
    // 序列化填充长度
    buffer[offset++] = packet->padding_length;
    
    // 序列化有效载荷
    if (packet->payload_length > 0 && packet->payload) {
        memcpy(buffer + offset, packet->payload, packet->payload_length);
        offset += packet->payload_length;
    }
    
    // 序列化填充
    if (packet->padding_length > 0 && packet->padding) {
        memcpy(buffer + offset, packet->padding, packet->padding_length);
        offset += packet->padding_length;
    }
    
    *written = offset;
    
    log_message(LOG_DEBUG, "Serialized SSH packet: %u bytes written", *written);
    
    return SSH_OK;
}

// 释放SSH数据包资源
void packet_free(ssh_packet_t *packet) {
    if (packet) {
        if (packet->payload) {
            free(packet->payload);
            packet->payload = NULL;
        }
        if (packet->padding) {
            free(packet->padding);
            packet->padding = NULL;
        }
        if (packet->mac) {
            free(packet->mac);
            packet->mac = NULL;
        }
        packet->payload_length = 0;
        packet->padding_length = 0;
        packet->mac_length = 0;
    }
}

// 清理SSH数据包上下文
void packet_cleanup_context(ssh_packet_context_t *ctx) {
    if (ctx) {
        if (ctx->mac_key) {
            // 安全清零MAC密钥
            volatile uint8_t *p = (volatile uint8_t *)ctx->mac_key;
            for (uint32_t i = 0; i < ctx->mac_key_length; i++) {
                p[i] = 0;
            }
            free(ctx->mac_key);
            ctx->mac_key = NULL;
        }
        ctx->mac_key_length = 0;
        ctx->sequence_number = 0;
    }
}

// 获取消息类型字符串描述
const char* packet_message_type_string(uint8_t message_type) {
    switch (message_type) {
        case SSH_MSG_DISCONNECT: return "SSH_MSG_DISCONNECT";
        case SSH_MSG_IGNORE: return "SSH_MSG_IGNORE";
        case SSH_MSG_UNIMPLEMENTED: return "SSH_MSG_UNIMPLEMENTED";
        case SSH_MSG_DEBUG: return "SSH_MSG_DEBUG";
        case SSH_MSG_SERVICE_REQUEST: return "SSH_MSG_SERVICE_REQUEST";
        case SSH_MSG_SERVICE_ACCEPT: return "SSH_MSG_SERVICE_ACCEPT";
        case SSH_MSG_KEXINIT: return "SSH_MSG_KEXINIT";
        case SSH_MSG_NEWKEYS: return "SSH_MSG_NEWKEYS";
        case SSH_MSG_KEXDH_INIT: return "SSH_MSG_KEXDH_INIT";
        case SSH_MSG_KEXDH_REPLY: return "SSH_MSG_KEXDH_REPLY";
        case SSH_MSG_USERAUTH_REQUEST: return "SSH_MSG_USERAUTH_REQUEST";
        case SSH_MSG_USERAUTH_FAILURE: return "SSH_MSG_USERAUTH_FAILURE";
        case SSH_MSG_USERAUTH_SUCCESS: return "SSH_MSG_USERAUTH_SUCCESS";
        case SSH_MSG_USERAUTH_BANNER: return "SSH_MSG_USERAUTH_BANNER";
        case SSH_MSG_GLOBAL_REQUEST: return "SSH_MSG_GLOBAL_REQUEST";
        case SSH_MSG_REQUEST_SUCCESS: return "SSH_MSG_REQUEST_SUCCESS";
        case SSH_MSG_REQUEST_FAILURE: return "SSH_MSG_REQUEST_FAILURE";
        case SSH_MSG_CHANNEL_OPEN: return "SSH_MSG_CHANNEL_OPEN";
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
        case SSH_MSG_CHANNEL_OPEN_FAILURE: return "SSH_MSG_CHANNEL_OPEN_FAILURE";
        case SSH_MSG_CHANNEL_WINDOW_ADJUST: return "SSH_MSG_CHANNEL_WINDOW_ADJUST";
        case SSH_MSG_CHANNEL_DATA: return "SSH_MSG_CHANNEL_DATA";
        case SSH_MSG_CHANNEL_EXTENDED_DATA: return "SSH_MSG_CHANNEL_EXTENDED_DATA";
        case SSH_MSG_CHANNEL_EOF: return "SSH_MSG_CHANNEL_EOF";
        case SSH_MSG_CHANNEL_CLOSE: return "SSH_MSG_CHANNEL_CLOSE";
        case SSH_MSG_CHANNEL_REQUEST: return "SSH_MSG_CHANNEL_REQUEST";
        case SSH_MSG_CHANNEL_SUCCESS: return "SSH_MSG_CHANNEL_SUCCESS";
        case SSH_MSG_CHANNEL_FAILURE: return "SSH_MSG_CHANNEL_FAILURE";
        default: return "UNKNOWN_MESSAGE_TYPE";
    }
}