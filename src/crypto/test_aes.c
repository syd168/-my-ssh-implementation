#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    printf("AES Encryption Test\n");
    printf("==================\n");
    
    // 测试数据
    const char* plaintext = "Hello, this is a test message for AES encryption!";
    printf("Original text: %s\n", plaintext);
    
    // AES上下文
    aes_context_t ctx;
    
    // 256位密钥（32字节）
    unsigned char key[AES_256_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    
    // IV
    unsigned char iv[AES_IV_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    
    // 初始化AES上下文
    aes_result_t result = aes_init(&ctx, key, AES_256_KEY_SIZE, iv);
    if (result != AES_SUCCESS) {
        printf("Failed to initialize AES context: %d\n", result);
        return 1;
    }
    
    printf("AES context initialized successfully\n");
    
    // 加密缓冲区
    int plaintext_len = strlen(plaintext);
    int max_ciphertext_len = ((plaintext_len / AES_BLOCK_SIZE) + 2) * AES_BLOCK_SIZE;
    unsigned char* ciphertext = malloc((size_t)max_ciphertext_len);
    if (!ciphertext) {
        printf("Failed to allocate memory for ciphertext\n");
        aes_cleanup(&ctx);
        return 1;
    }
    
    int ciphertext_len;
    
    // 执行加密
    result = aes_encrypt_cbc(&ctx, (const unsigned char*)plaintext, plaintext_len, ciphertext, &ciphertext_len);
    if (result != AES_SUCCESS) {
        printf("Encryption failed: %d\n", result);
        free(ciphertext);
        aes_cleanup(&ctx);
        return 1;
    }
    
    printf("Encryption successful. Ciphertext length: %d\n", ciphertext_len);
    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");
    
    // 解密缓冲区
    unsigned char* decrypted_text = malloc((size_t)max_ciphertext_len);
    if (!decrypted_text) {
        printf("Failed to allocate memory for decrypted text\n");
        free(ciphertext);
        aes_cleanup(&ctx);
        return 1;
    }
    
    int decrypted_len;
    
    // 执行解密
    result = aes_decrypt_cbc(&ctx, ciphertext, ciphertext_len, decrypted_text, &decrypted_len);
    if (result != AES_SUCCESS) {
        printf("Decryption failed: %d\n", result);
        free(ciphertext);
        free(decrypted_text);
        aes_cleanup(&ctx);
        return 1;
    }
    
    // 添加字符串结束符
    decrypted_text[decrypted_len] = '\0';
    
    printf("Decryption successful. Decrypted text: %s\n", decrypted_text);
    
    // 验证结果
    if (decrypted_len == plaintext_len && memcmp(plaintext, decrypted_text, (size_t)plaintext_len) == 0) {
        printf("Test PASSED: Decrypted text matches original\n");
    } else {
        printf("Test FAILED: Decrypted text does not match original\n");
        printf("Original length: %d, Decrypted length: %d\n", plaintext_len, decrypted_len);
    }
    
    // 清理资源
    free(ciphertext);
    free(decrypted_text);
    aes_cleanup(&ctx);
    
    return 0;
}