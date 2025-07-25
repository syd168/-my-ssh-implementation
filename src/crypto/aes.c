#include "aes.h"
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "../common/common.h"

// 生成随机IV
aes_result_t aes_generate_iv(unsigned char *iv) {
    if (!iv) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        log_message(LOG_ERROR, "Failed to open /dev/urandom for IV generation");
        return AES_ERROR_ENCRYPT_FAILED;
    }
    
    ssize_t bytes_read = read(fd, iv, AES_IV_SIZE);
    close(fd);
    
    if (bytes_read != AES_IV_SIZE) {
        log_message(LOG_ERROR, "Failed to read enough random bytes for IV");
        return AES_ERROR_ENCRYPT_FAILED;
    }
    
    return AES_SUCCESS;
}

// 初始化AES上下文
aes_result_t aes_init(aes_context_t *ctx, const unsigned char *key, int key_len, const unsigned char *iv) {
    if (!ctx || !key) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    if (key_len != AES_128_KEY_SIZE && key_len != AES_256_KEY_SIZE) {
        return AES_ERROR_INVALID_KEY_SIZE;
    }
    
    memset(ctx, 0, sizeof(aes_context_t));
    
    // 复制密钥
    memcpy(ctx->key, key, key_len);
    ctx->key_len = key_len;
    
    // 复制或生成IV
    if (iv) {
        memcpy(ctx->iv, iv, AES_IV_SIZE);
    } else {
        // 如果没有提供IV，则生成随机IV
        if (aes_generate_iv(ctx->iv) != AES_SUCCESS) {
            return AES_ERROR_ENCRYPT_FAILED;
        }
    }
    
    ctx->initialized = 1;
    return AES_SUCCESS;
}

// PKCS#7填充
int aes_pkcs7_pad(unsigned char *data, int data_len, int block_size) {
    if (!data || block_size <= 0) {
        return -1;
    }
    
    // 检查是否有足够的空间进行填充
    int padding = block_size - (data_len % block_size);
    // 这里我们假设调用者已确保有足够的空间
    
    for (int i = 0; i < padding; i++) {
        data[data_len + i] = (unsigned char)padding;
    }
    
    return data_len + padding;
}

// PKCS#7去填充
int aes_pkcs7_unpad(unsigned char *data, int data_len) {
    if (!data || data_len <= 0) {
        return -1;
    }
    
    if (data_len % AES_BLOCK_SIZE != 0) {
        return -1; // 数据长度必须是块大小的倍数
    }
    
    unsigned char padding_value = data[data_len - 1];
    
    // 检查填充值是否合理
    if (padding_value == 0 || padding_value > AES_BLOCK_SIZE) {
        return -1;
    }
    
    // 检查所有填充字节是否相同
    for (int i = data_len - padding_value; i < data_len; i++) {
        if (data[i] != padding_value) {
            return -1;
        }
    }
    
    return data_len - padding_value;
}

// 简化的AES-CBC加密实现（用于学习目的）
aes_result_t aes_encrypt_cbc(aes_context_t *ctx, const unsigned char *plaintext, int plaintext_len,
                            unsigned char *ciphertext, int *ciphertext_len) {
    if (!ctx || !plaintext || !ciphertext || !ciphertext_len) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    if (!ctx->initialized) {
        return AES_ERROR_NOT_INITIALIZED;
    }
    
    if (plaintext_len < 0) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    // 计算填充后的长度
    int padded_len = ((plaintext_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    
    // 分配临时缓冲区用于填充
    unsigned char *padded_data = malloc((size_t)padded_len);
    if (!padded_data) {
        return AES_ERROR_ENCRYPT_FAILED;
    }
    
    // 复制原始数据
    memcpy(padded_data, plaintext, (size_t)plaintext_len);
    
    // 执行PKCS#7填充
    int final_len = aes_pkcs7_pad(padded_data, plaintext_len, AES_BLOCK_SIZE);
    if (final_len != padded_len) {
        free(padded_data);
        return AES_ERROR_ENCRYPT_FAILED;
    }
    
    // 简化的AES加密实现（仅用于演示）
    // 在实际应用中，这里应该使用真正的AES加密库
    for (int i = 0; i < final_len; i++) {
        // 这是一个简化的"加密"过程，仅用于演示
        // 实际的AES实现会更复杂
        ciphertext[i] = padded_data[i] ^ ctx->key[i % ctx->key_len] ^ ctx->iv[i % AES_IV_SIZE];
    }
    
    *ciphertext_len = final_len;
    free(padded_data);
    
    log_message(LOG_DEBUG, "AES-CBC encryption performed (simplified implementation)");
    return AES_SUCCESS;
}

// 简化的AES-CBC解密实现（用于学习目的）
aes_result_t aes_decrypt_cbc(aes_context_t *ctx, const unsigned char *ciphertext, int ciphertext_len,
                            unsigned char *plaintext, int *plaintext_len) {
    if (!ctx || !ciphertext || !plaintext || !plaintext_len) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    if (!ctx->initialized) {
        return AES_ERROR_NOT_INITIALIZED;
    }
    
    if (ciphertext_len <= 0 || ciphertext_len % AES_BLOCK_SIZE != 0) {
        return AES_ERROR_INVALID_PARAM;
    }
    
    // 简化的AES解密实现（仅用于演示）
    // 在实际应用中，这里应该使用真正的AES解密库
    for (int i = 0; i < ciphertext_len; i++) {
        // 这是一个简化的"解密"过程，仅用于演示
        plaintext[i] = ciphertext[i] ^ ctx->key[i % ctx->key_len] ^ ctx->iv[i % AES_IV_SIZE];
    }
    
    // 去除PKCS#7填充
    int unpadded_len = aes_pkcs7_unpad(plaintext, ciphertext_len);
    if (unpadded_len < 0) {
        return AES_ERROR_DECRYPT_FAILED;
    }
    
    *plaintext_len = unpadded_len;
    
    log_message(LOG_DEBUG, "AES-CBC decryption performed (simplified implementation)");
    return AES_SUCCESS;
}

// 清理AES上下文（安全清零）
void aes_cleanup(aes_context_t *ctx) {
    if (ctx) {
        // 安全地清零内存
        volatile unsigned char *p = (volatile unsigned char *)ctx;
        for (size_t i = 0; i < sizeof(aes_context_t); i++) {
            p[i] = 0;
        }
    }
}