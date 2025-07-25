#include "ssh_packet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    printf("SSH Packet Test\n");
    printf("===============\n");
    
    // 初始化数据包上下文
    ssh_packet_context_t ctx;
    ssh_result_t result = packet_init_context(&ctx);
    if (result != SSH_OK) {
        printf("Failed to initialize packet context: %d\n", result);
        return 1;
    }
    
    printf("Packet context initialized successfully\n");
    
    // 创建测试有效载荷
    const char* test_payload = "SSH-2.0-MySSH_1.0 Test Message";
    uint32_t payload_length = strlen(test_payload);
    
    printf("Creating test packet with payload: %s\n", test_payload);
    
    // 创建SSH数据包
    ssh_packet_t packet;
    result = packet_create(&ctx, (const uint8_t*)test_payload, payload_length, &packet);
    if (result != SSH_OK) {
        printf("Failed to create packet: %d\n", result);
        packet_cleanup_context(&ctx);
        return 1;
    }
    
    printf("Packet created successfully:\n");
    printf("  Packet length: %u\n", packet.packet_length);
    printf("  Payload length: %u\n", packet.payload_length);
    printf("  Padding length: %u\n", packet.padding_length);
    
    // 序列化数据包
    uint8_t serialized_buffer[1024];
    uint32_t written;
    result = packet_serialize(&ctx, &packet, serialized_buffer, sizeof(serialized_buffer), &written);
    if (result != SSH_OK) {
        printf("Failed to serialize packet: %d\n", result);
        packet_free(&packet);
        packet_cleanup_context(&ctx);
        return 1;
    }
    
    printf("Packet serialized successfully: %u bytes written\n", written);
    
    // 解析序列化的数据包
    ssh_packet_t parsed_packet;
    result = packet_parse(&ctx, serialized_buffer, written, &parsed_packet);
    if (result != SSH_OK) {
        printf("Failed to parse packet: %d\n", result);
        packet_free(&packet);
        packet_cleanup_context(&ctx);
        return 1;
    }
    
    printf("Packet parsed successfully:\n");
    printf("  Packet length: %u\n", parsed_packet.packet_length);
    printf("  Payload length: %u\n", parsed_packet.payload_length);
    printf("  Padding length: %u\n", parsed_packet.padding_length);
    
    // 验证解析的数据包与原始数据包是否一致
    if (parsed_packet.packet_length == packet.packet_length &&
        parsed_packet.payload_length == packet.payload_length &&
        parsed_packet.padding_length == packet.padding_length &&
        memcmp(parsed_packet.payload, packet.payload, packet.payload_length) == 0) {
        printf("Test PASSED: Parsed packet matches original packet\n");
    } else {
        printf("Test FAILED: Parsed packet does not match original packet\n");
        packet_free(&packet);
        packet_free(&parsed_packet);
        packet_cleanup_context(&ctx);
        return 1;
    }
    
    // 测试消息类型字符串功能
    printf("\nTesting message type strings:\n");
    uint8_t test_types[] = {
        SSH_MSG_DISCONNECT,
        SSH_MSG_KEXINIT,
        SSH_MSG_NEWKEYS,
        SSH_MSG_USERAUTH_REQUEST,
        SSH_MSG_CHANNEL_DATA,
        255  // 未知类型
    };
    
    // 修复符号比较警告
    for (size_t i = 0; i < sizeof(test_types); i++) {
        printf("  Message type %u: %s\n", test_types[i], packet_message_type_string(test_types[i]));
    }
    
    // 清理资源
    packet_free(&packet);
    packet_free(&parsed_packet);
    packet_cleanup_context(&ctx);
    
    printf("\nSSH Packet Test Complete\n");
    return 0;
}