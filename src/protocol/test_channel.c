#include "channel.h"
#include "../common/logger.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    printf("SSH Channel Management Test\n");
    printf("===========================\n");
    
    // 初始化日志系统
    init_logger(LOG_DEBUG);
    
    // 初始化通道管理器
    ssh_channel_manager_t manager;
    ssh_result_t result = channel_manager_init(&manager, 10);
    if (result != SSH_OK) {
        printf("Failed to initialize channel manager: %d\n", result);
        return 1;
    }
    
    printf("Channel manager initialized successfully\n");
    
    // 测试1: 创建通道
    printf("\nTest 1: Creating channels...\n");
    
    ssh_channel_t *session_channel = NULL;
    result = channel_create(&manager, SSH_CHANNEL_SESSION, &session_channel);
    if (result != SSH_OK) {
        printf("Failed to create session channel: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    printf("Session channel created successfully, ID: %u\n", session_channel->local_channel_id);
    
    ssh_channel_t *tcp_channel = NULL;
    result = channel_create(&manager, SSH_CHANNEL_DIRECT_TCP, &tcp_channel);
    if (result != SSH_OK) {
        printf("Failed to create TCP channel: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    printf("TCP channel created successfully, ID: %u\n", tcp_channel->local_channel_id);
    printf("Total channels: %u\n", manager.channel_count);
    
    // 测试2: 初始化通道加密
    printf("\nTest 2: Initializing channel encryption...\n");
    
    unsigned char test_key[32] = {0};
    unsigned char test_iv[16] = {0};
    
    // 生成测试密钥和IV
    for (int i = 0; i < 32; i++) {
        test_key[i] = i;
    }
    for (int i = 0; i < 16; i++) {
        test_iv[i] = i;
    }
    
    result = channel_init_encryption(session_channel, test_key, test_key, 32, test_iv, test_iv);
    if (result != SSH_OK) {
        printf("Failed to initialize channel encryption: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    printf("Channel encryption initialized successfully\n");
    
    // 测试3: 初始化通道HMAC
    printf("\nTest 3: Initializing channel HMAC...\n");
    
    unsigned char test_hmac_key[32] = {0};
    for (int i = 0; i < 32; i++) {
        test_hmac_key[i] = i + 32;
    }
    
    result = channel_init_hmac(session_channel, test_hmac_key, 32, test_hmac_key, 32);
    if (result != SSH_OK) {
        printf("Failed to initialize channel HMAC: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    printf("Channel HMAC initialized successfully\n");
    
    // 测试4: 创建通道打开消息
    printf("\nTest 4: Creating channel open message...\n");
    
    uint8_t open_message[256];
    uint32_t open_message_len;
    result = channel_create_open_message(session_channel, open_message, sizeof(open_message), &open_message_len);
    if (result != SSH_OK) {
        printf("Failed to create channel open message: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    printf("Channel open message created successfully: %u bytes\n", open_message_len);
    printf("  Message type: %d\n", open_message[0]);
    printf("  Channel ID: %u\n", 
           (open_message[5] << 24) | (open_message[6] << 16) | (open_message[7] << 8) | open_message[8]);
    
    // 测试5: 解析通道打开消息
    printf("\nTest 5: Parsing channel open message...\n");
    
    ssh_channel_t parsed_channel;
    memset(&parsed_channel, 0, sizeof(parsed_channel));
    
    result = channel_parse_open_message(&parsed_channel, open_message, open_message_len);
    if (result != SSH_OK) {
        printf("Failed to parse channel open message: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    printf("Channel open message parsed successfully\n");
    printf("  Channel type: %s\n", parsed_channel.channel_type);
    printf("  Remote channel ID: %u\n", parsed_channel.remote_channel_id);
    printf("  Remote window size: %u\n", parsed_channel.remote_window_size);
    printf("  Remote max packet size: %u\n", parsed_channel.remote_max_packet_size);
    
    // 设置session_channel的remote_channel_id用于测试
    session_channel->remote_channel_id = session_channel->local_channel_id;
    
    // 测试6: 创建通道数据消息
    printf("\nTest 6: Creating channel data message...\n");
    
    const char* test_data = "Hello, SSH Channel!";
    uint8_t data_message[256];
    uint32_t data_message_len;
    
    result = channel_create_data_message(session_channel, 
                                        (const unsigned char*)test_data, 
                                        strlen(test_data),
                                        data_message, 
                                        sizeof(data_message), 
                                        &data_message_len);
    if (result != SSH_OK) {
        printf("Failed to create channel data message: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    printf("Channel data message created successfully: %u bytes\n", data_message_len);
    printf("  Message type: %d\n", data_message[0]);
    printf("  Recipient channel ID: %u\n", 
           (data_message[1] << 24) | (data_message[2] << 16) | (data_message[3] << 8) | data_message[4]);
    printf("  Data length: %u\n", 
           (data_message[5] << 24) | (data_message[6] << 16) | (data_message[7] << 8) | data_message[8]);
    
    // 测试7: 解析通道数据消息
    printf("\nTest 7: Parsing channel data message...\n");
    
    unsigned char parsed_data[256];
    uint32_t parsed_data_len = sizeof(parsed_data);
    
    result = channel_parse_data_message(session_channel, data_message, data_message_len, 
                                       parsed_data, &parsed_data_len);
    if (result != SSH_OK) {
        printf("Failed to parse channel data message: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    parsed_data[parsed_data_len] = '\0';
    printf("Channel data message parsed successfully: %u bytes\n", parsed_data_len);
    printf("  Data: %s\n", parsed_data);
    
    // 测试8: 关闭通道
    printf("\nTest 8: Closing channels...\n");
    
    result = channel_close(session_channel);
    if (result != SSH_OK) {
        printf("Failed to close session channel: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    result = channel_close(tcp_channel);
    if (result != SSH_OK) {
        printf("Failed to close TCP channel: %d\n", result);
        channel_manager_cleanup(&manager);
        return 1;
    }
    
    printf("Channels closed successfully\n");
    
    // 清理资源
    channel_manager_cleanup(&manager);
    
    printf("\nAll tests passed!\n");
    printf("SSH Channel Management Implementation Verified\n");
    
    return 0;
}