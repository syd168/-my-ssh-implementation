#include "channel.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 初始化通道管理器
ssh_result_t channel_manager_init(ssh_channel_manager_t *manager, uint32_t max_channels) {
    if (!manager) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(manager, 0, sizeof(ssh_channel_manager_t));
    
    manager->channels = calloc(max_channels, sizeof(ssh_channel_t));
    if (!manager->channels) {
        return SSH_ERROR_MEMORY;
    }
    
    manager->max_channels = max_channels;
    manager->channel_count = 0;
    manager->next_channel_id = 1; // 通道ID从1开始
    
    log_message(LOG_DEBUG, "Channel manager initialized with max channels: %u", max_channels);
    return SSH_OK;
}

// 创建新的SSH通道
ssh_result_t channel_create(ssh_channel_manager_t *manager, 
                           const char *channel_type, 
                           ssh_channel_t **channel) {
    if (!manager || !channel_type || !channel) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 检查是否还有空间创建新通道
    if (manager->channel_count >= manager->max_channels) {
        log_message(LOG_WARN, "Maximum channel count reached: %u", manager->max_channels);
        return SSH_ERROR_MEMORY; // 改为SSH_ERROR_MEMORY，因为没有SSH_ERROR_RESOURCE定义
    }
    
    // 查找一个空闲的通道槽位
    ssh_channel_t *new_channel = NULL;
    // 移除未使用的变量channel_index
    // uint32_t channel_index = 0;
    
    for (uint32_t i = 0; i < manager->max_channels; i++) {
        if (manager->channels[i].state == SSH_CHANNEL_STATE_CLOSED) {
            new_channel = &manager->channels[i];
            // channel_index = i;
            break;
        }
        
        // 如果是未初始化的通道
        if (manager->channels[i].local_channel_id == 0) {
            new_channel = &manager->channels[i];
            // channel_index = i;
            break;
        }
    }
    
    if (!new_channel) {
        log_message(LOG_ERROR, "No available channel slot found");
        return SSH_ERROR_MEMORY; // 改为SSH_ERROR_MEMORY
    }
    
    // 初始化通道
    memset(new_channel, 0, sizeof(ssh_channel_t));
    new_channel->local_channel_id = manager->next_channel_id++;
    new_channel->local_window_size = 1024 * 1024; // 1MB窗口大小
    new_channel->local_max_packet_size = 32768;   // 32KB最大包大小
    new_channel->state = SSH_CHANNEL_STATE_OPEN;
    strncpy(new_channel->channel_type, channel_type, sizeof(new_channel->channel_type) - 1);
    new_channel->channel_type[sizeof(new_channel->channel_type) - 1] = '\0';
    
    manager->channel_count++;
    *channel = new_channel;
    
    log_message(LOG_DEBUG, "Created new channel %u of type: %s", 
                new_channel->local_channel_id, channel_type);
    return SSH_OK;
}

// 打开SSH通道
ssh_result_t channel_open(ssh_channel_t *channel, int socket_fd) {
    if (!channel) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    channel->socket_fd = socket_fd;
    channel->state = SSH_CHANNEL_STATE_OPEN;
    
    log_message(LOG_DEBUG, "Channel %u opened with socket fd: %d", 
                channel->local_channel_id, socket_fd);
    return SSH_OK;
}

// 关闭SSH通道
ssh_result_t channel_close(ssh_channel_t *channel) {
    if (!channel) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (channel->state != SSH_CHANNEL_STATE_CLOSED) {
        channel->state = SSH_CHANNEL_STATE_CLOSED;
        
        // 清理加密上下文
        aes_cleanup(&channel->encrypt_ctx);
        aes_cleanup(&channel->decrypt_ctx);
        
        // 清理HMAC密钥
        memset(channel->send_hmac_key, 0, sizeof(channel->send_hmac_key));
        memset(channel->recv_hmac_key, 0, sizeof(channel->recv_hmac_key));
        channel->send_hmac_key_len = 0;
        channel->recv_hmac_key_len = 0;
        
        // 重置序列号
        channel->send_seq = 0;
        channel->recv_seq = 0;
        
        log_message(LOG_DEBUG, "Channel %u closed", channel->local_channel_id);
    }
    
    return SSH_OK;
}

// 释放SSH通道
ssh_result_t channel_free(ssh_channel_t *channel) {
    if (!channel) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 先关闭通道
    channel_close(channel);
    
    // 重置通道状态
    channel->local_channel_id = 0;
    channel->remote_channel_id = 0;
    channel->local_window_size = 0;
    channel->remote_window_size = 0;
    channel->local_max_packet_size = 0;
    channel->remote_max_packet_size = 0;
    channel->state = SSH_CHANNEL_STATE_CLOSED;
    channel->channel_type[0] = '\0';
    channel->socket_fd = -1;
    
    // 清理通道特定数据
    if (channel->channel_data) {
        free(channel->channel_data);
        channel->channel_data = NULL;
    }
    
    log_message(LOG_DEBUG, "Channel freed");
    return SSH_OK;
}

// 初始化通道加密
ssh_result_t channel_init_encryption(ssh_channel_t *channel,
                                    const unsigned char *encryption_key,
                                    const unsigned char *decryption_key,
                                    uint32_t key_len,
                                    const unsigned char *encryption_iv,
                                    const unsigned char *decryption_iv) {
    if (!channel || !encryption_key || !decryption_key || !encryption_iv || !decryption_iv) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 初始化加密上下文
    aes_result_t result = aes_init(&channel->encrypt_ctx, encryption_key, key_len, encryption_iv);
    if (result != AES_SUCCESS) {
        log_message(LOG_ERROR, "Failed to initialize encryption context");
        return SSH_ERROR_CRYPTO;
    }
    
    // 初始化解密上下文
    result = aes_init(&channel->decrypt_ctx, decryption_key, key_len, decryption_iv);
    if (result != AES_SUCCESS) {
        log_message(LOG_ERROR, "Failed to initialize decryption context");
        aes_cleanup(&channel->encrypt_ctx);
        return SSH_ERROR_CRYPTO;
    }
    
    log_message(LOG_DEBUG, "Channel encryption initialized");
    return SSH_OK;
}

// 初始化通道HMAC
ssh_result_t channel_init_hmac(ssh_channel_t *channel,
                              const unsigned char *send_hmac_key,
                              uint32_t send_hmac_key_len,
                              const unsigned char *recv_hmac_key,
                              uint32_t recv_hmac_key_len) {
    if (!channel || !send_hmac_key || !recv_hmac_key) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (send_hmac_key_len > sizeof(channel->send_hmac_key) || 
        recv_hmac_key_len > sizeof(channel->recv_hmac_key)) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 复制发送HMAC密钥
    memcpy(channel->send_hmac_key, send_hmac_key, send_hmac_key_len);
    channel->send_hmac_key_len = send_hmac_key_len;
    
    // 复制接收HMAC密钥
    memcpy(channel->recv_hmac_key, recv_hmac_key, recv_hmac_key_len);
    channel->recv_hmac_key_len = recv_hmac_key_len;
    
    log_message(LOG_DEBUG, "Channel HMAC initialized");
    return SSH_OK;
}

// 加密并发送数据
ssh_result_t channel_send_encrypted_data(ssh_channel_t *channel,
                                        const unsigned char *data,
                                        uint32_t data_len) {
    if (!channel || !data) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (channel->state != SSH_CHANNEL_STATE_OPEN) {
        log_message(LOG_WARN, "Attempt to send data on closed channel %u", channel->local_channel_id);
        return SSH_ERROR_INVALID_PARAM; // 改为SSH_ERROR_INVALID_PARAM
    }
    
    // 加密数据
    unsigned char *encrypted_data = malloc(data_len + AES_BLOCK_SIZE);
    if (!encrypted_data) {
        log_message(LOG_ERROR, "Failed to allocate memory for encrypted data");
        return SSH_ERROR_MEMORY;
    }
    
    int encrypted_len = 0;
    aes_result_t result = aes_encrypt_cbc(&channel->encrypt_ctx, data, data_len, 
                                         encrypted_data, &encrypted_len);
    
    if (result != AES_SUCCESS) {
        log_message(LOG_ERROR, "Failed to encrypt data for channel %u", channel->local_channel_id);
        free(encrypted_data);
        return SSH_ERROR_CRYPTO;
    }
    
    // 发送加密数据
    ssh_result_t ssh_result = send_data(channel->socket_fd, (char*)encrypted_data, encrypted_len);
    free(encrypted_data);
    
    if (ssh_result == SSH_OK) {
        channel->send_seq++; // 增加发送序列号
        log_message(LOG_DEBUG, "Sent %d encrypted bytes on channel %u", 
                    encrypted_len, channel->local_channel_id);
    }
    
    return ssh_result;
}

// 接收并解密数据
ssh_result_t channel_receive_decrypted_data(ssh_channel_t *channel,
                                           unsigned char *buffer,
                                           uint32_t buffer_len,
                                           uint32_t *received_len) {
    if (!channel || !buffer || !received_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (channel->state != SSH_CHANNEL_STATE_OPEN) {
        log_message(LOG_WARN, "Attempt to receive data on closed channel %u", channel->local_channel_id);
        return SSH_ERROR_INVALID_PARAM; // 改为SSH_ERROR_INVALID_PARAM
    }
    
    // 接收加密数据（简化实现，实际应该处理完整的SSH包）
    char *encrypted_buffer = malloc(buffer_len + AES_BLOCK_SIZE);
    if (!encrypted_buffer) {
        log_message(LOG_ERROR, "Failed to allocate memory for encrypted buffer");
        return SSH_ERROR_MEMORY;
    }
    
    size_t received;
    ssh_result_t result = receive_data(channel->socket_fd, encrypted_buffer, buffer_len, &received);
    if (result != SSH_OK) {
        free(encrypted_buffer);
        return result;
    }
    
    // 解密数据
    int decrypted_len = 0;
    aes_result_t aes_result = aes_decrypt_cbc(&channel->decrypt_ctx, 
                                             (unsigned char*)encrypted_buffer, 
                                             received, 
                                             buffer, 
                                             &decrypted_len);
    free(encrypted_buffer);
    
    if (aes_result != AES_SUCCESS) {
        log_message(LOG_ERROR, "Failed to decrypt data for channel %u", channel->local_channel_id);
        return SSH_ERROR_CRYPTO;
    }
    
    *received_len = decrypted_len;
    channel->recv_seq++; // 增加接收序列号
    
    log_message(LOG_DEBUG, "Received and decrypted %u bytes on channel %u", 
                decrypted_len, channel->local_channel_id);
    return SSH_OK;
}

// 创建通道打开消息
ssh_result_t channel_create_open_message(ssh_channel_t *channel,
                                        uint8_t *buffer,
                                        uint32_t buffer_len,
                                        uint32_t *message_len) {
    if (!channel || !buffer || !message_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 计算所需缓冲区大小
    uint32_t required_len = 1 + 4 + strlen(channel->channel_type) + 4 + 4 + 4;
    
    if (buffer_len < required_len) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint32_t offset = 0;
    
    // 消息类型
    buffer[offset++] = SSH_MSG_CHANNEL_OPEN;
    
    // 通道类型长度和内容
    uint32_t type_len = strlen(channel->channel_type);
    buffer[offset++] = (type_len >> 24) & 0xFF;
    buffer[offset++] = (type_len >> 16) & 0xFF;
    buffer[offset++] = (type_len >> 8) & 0xFF;
    buffer[offset++] = type_len & 0xFF;
    memcpy(buffer + offset, channel->channel_type, type_len);
    offset += type_len;
    
    // 发送者通道ID
    buffer[offset++] = (channel->local_channel_id >> 24) & 0xFF;
    buffer[offset++] = (channel->local_channel_id >> 16) & 0xFF;
    buffer[offset++] = (channel->local_channel_id >> 8) & 0xFF;
    buffer[offset++] = channel->local_channel_id & 0xFF;
    
    // 初始窗口大小
    buffer[offset++] = (channel->local_window_size >> 24) & 0xFF;
    buffer[offset++] = (channel->local_window_size >> 16) & 0xFF;
    buffer[offset++] = (channel->local_window_size >> 8) & 0xFF;
    buffer[offset++] = channel->local_window_size & 0xFF;
    
    // 最大包大小
    buffer[offset++] = (channel->local_max_packet_size >> 24) & 0xFF;
    buffer[offset++] = (channel->local_max_packet_size >> 16) & 0xFF;
    buffer[offset++] = (channel->local_max_packet_size >> 8) & 0xFF;
    buffer[offset++] = channel->local_max_packet_size & 0xFF;
    
    *message_len = offset;
    
    log_message(LOG_DEBUG, "Created channel open message for channel %u", channel->local_channel_id);
    return SSH_OK;
}

// 解析通道打开消息
ssh_result_t channel_parse_open_message(ssh_channel_t *channel,
                                       const uint8_t *data,
                                       uint32_t data_len) {
    if (!channel || !data) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (data_len < 5) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t offset = 0;
    
    // 检查消息类型
    if (data[offset++] != SSH_MSG_CHANNEL_OPEN) {
        return SSH_ERROR_PROTOCOL;
    }
    
    // 解析通道类型
    if (offset + 4 > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t type_len = (data[offset] << 24) | (data[offset+1] << 16) | 
                       (data[offset+2] << 8) | data[offset+3];
    offset += 4;
    
    if (offset + type_len > data_len || type_len >= sizeof(channel->channel_type)) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memcpy(channel->channel_type, data + offset, type_len);
    channel->channel_type[type_len] = '\0';
    offset += type_len;
    
    // 解析发送者通道ID
    if (offset + 4 > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    channel->remote_channel_id = (data[offset] << 24) | (data[offset+1] << 16) | 
                                (data[offset+2] << 8) | data[offset+3];
    offset += 4;
    
    // 解析初始窗口大小
    if (offset + 4 > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    channel->remote_window_size = (data[offset] << 24) | (data[offset+1] << 16) | 
                                 (data[offset+2] << 8) | data[offset+3];
    offset += 4;
    
    // 解析最大包大小
    if (offset + 4 > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    channel->remote_max_packet_size = (data[offset] << 24) | (data[offset+1] << 16) | 
                                     (data[offset+2] << 8) | data[offset+3];
    offset += 4;
    
    channel->state = SSH_CHANNEL_STATE_OPEN;
    
    log_message(LOG_DEBUG, "Parsed channel open message: channel %u, type %s", 
                channel->remote_channel_id, channel->channel_type);
    return SSH_OK;
}

// 创建通道数据消息
ssh_result_t channel_create_data_message(ssh_channel_t *channel,
                                        const unsigned char *payload,
                                        uint32_t payload_len,
                                        uint8_t *buffer,
                                        uint32_t buffer_len,
                                        uint32_t *message_len) {
    if (!channel || !payload || !buffer || !message_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 计算所需缓冲区大小
    uint32_t required_len = 1 + 4 + 4 + payload_len;
    
    if (buffer_len < required_len) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint32_t offset = 0;
    
    // 消息类型
    buffer[offset++] = SSH_MSG_CHANNEL_DATA;
    
    // 接收者通道ID
    buffer[offset++] = (channel->remote_channel_id >> 24) & 0xFF;
    buffer[offset++] = (channel->remote_channel_id >> 16) & 0xFF;
    buffer[offset++] = (channel->remote_channel_id >> 8) & 0xFF;
    buffer[offset++] = channel->remote_channel_id & 0xFF;
    
    // 数据长度
    buffer[offset++] = (payload_len >> 24) & 0xFF;
    buffer[offset++] = (payload_len >> 16) & 0xFF;
    buffer[offset++] = (payload_len >> 8) & 0xFF;
    buffer[offset++] = payload_len & 0xFF;
    
    // 数据
    memcpy(buffer + offset, payload, payload_len);
    offset += payload_len;
    
    *message_len = offset;
    
    log_message(LOG_DEBUG, "Created channel data message with %u bytes payload", payload_len);
    return SSH_OK;
}

// 解析通道数据消息
ssh_result_t channel_parse_data_message(ssh_channel_t *channel,
                                       const uint8_t *data,
                                       uint32_t data_len,
                                       unsigned char *payload,
                                       uint32_t *payload_len) {
    if (!channel || !data || !payload || !payload_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (data_len < 9) { // 最小消息长度：类型(1) + 通道ID(4) + 长度(4)
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t offset = 0;
    
    // 检查消息类型
    if (data[offset++] != SSH_MSG_CHANNEL_DATA) {
        return SSH_ERROR_PROTOCOL;
    }
    
    // 解析接收者通道ID
    if (offset + 4 > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t recipient_channel = (data[offset] << 24) | (data[offset+1] << 16) | 
                                (data[offset+2] << 8) | data[offset+3];
    offset += 4;
    
    // 检查通道ID是否匹配
    if (recipient_channel != channel->local_channel_id) {
        log_message(LOG_WARN, "Recipient channel ID mismatch: expected %u, got %u", 
                    channel->local_channel_id, recipient_channel);
        return SSH_ERROR_PROTOCOL;
    }
    
    // 解析数据长度
    if (offset + 4 > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t data_length = (data[offset] << 24) | (data[offset+1] << 16) | 
                          (data[offset+2] << 8) | data[offset+3];
    offset += 4;
    
    // 检查缓冲区是否足够
    if (offset + data_length > data_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (data_length > *payload_len) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    // 复制数据
    memcpy(payload, data + offset, data_length);
    *payload_len = data_length;
    offset += data_length;
    
    log_message(LOG_DEBUG, "Parsed channel data message with %u bytes payload", data_length);
    return SSH_OK;
}

// 清理通道管理器
void channel_manager_cleanup(ssh_channel_manager_t *manager) {
    if (manager) {
        if (manager->channels) {
            // 关闭所有通道
            for (uint32_t i = 0; i < manager->max_channels; i++) {
                if (manager->channels[i].local_channel_id != 0) {
                    channel_free(&manager->channels[i]);
                }
            }
            
            free(manager->channels);
            manager->channels = NULL;
        }
        
        manager->channel_count = 0;
        manager->max_channels = 0;
        manager->next_channel_id = 1;
        
        log_message(LOG_DEBUG, "Channel manager cleaned up");
    }
}