#include "ssh_protocol.h"
#include "../crypto/aes.h"
#include "../common/logger.h"
#include <string.h>

/**
 * 加密上下文初始化
 * @param ctx 加密上下文
 * @return SSH操作结果
 */
ssh_result_t ssh_encryption_context_init(ssh_encryption_context_t *ctx) {
    if (!ctx) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(ssh_encryption_context_t));
    ctx->key_len = 0;
    ctx->encryption_enabled = 0;
    ctx->decryption_enabled = 0;
    
    return SSH_OK;
}

/**
 * 启用SSH连接的加密功能
 * @param conn SSH连接上下文
 * @param encryption_key 加密密钥
 * @param decryption_key 解密密钥
 * @param key_len 密钥长度
 * @param encryption_iv 加密IV
 * @param decryption_iv 解密IV
 * @return SSH操作结果
 */
ssh_result_t ssh_enable_encryption(ssh_connection_t *conn, 
                                  const unsigned char *encryption_key,
                                  const unsigned char *decryption_key,
                                  int key_len,
                                  const unsigned char *encryption_iv,
                                  const unsigned char *decryption_iv) {
    if (!conn || !encryption_key || !decryption_key || !encryption_iv || !decryption_iv) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (key_len != AES_128_KEY_SIZE && key_len != AES_256_KEY_SIZE) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 设置加密密钥和IV
    memcpy(conn->encryption_ctx.encryption_key, encryption_key, key_len);
    memcpy(conn->encryption_ctx.decryption_key, decryption_key, key_len);
    memcpy(conn->encryption_ctx.encryption_iv, encryption_iv, AES_IV_SIZE);
    memcpy(conn->encryption_ctx.decryption_iv, decryption_iv, AES_IV_SIZE);
    conn->encryption_ctx.key_len = key_len;
    conn->encryption_ctx.encryption_enabled = 1;
    conn->encryption_ctx.decryption_enabled = 1;
    
    log_message(LOG_INFO, "SSH encryption enabled with %d-bit keys", key_len * 8);
    return SSH_OK;
}


/**
 * 加密数据
 * @param conn SSH连接上下文
 * @param plaintext 明文数据
 * @param plaintext_len 明文长度
 * @param ciphertext 密文输出缓冲区
 * @param ciphertext_len 密文长度输出
 * @return SSH操作结果
 */
ssh_result_t ssh_encrypt_data(ssh_connection_t *conn, 
                             const unsigned char *plaintext, 
                             int plaintext_len,
                             unsigned char *ciphertext, 
                             int *ciphertext_len) {
    if (!conn || !plaintext || !ciphertext || !ciphertext_len) {
        return SSH_ERROR_INVALID_PARAM;
    }

    if (!conn->encryption_ctx.encryption_enabled) {
        return SSH_ERROR_CRYPTO;
    }

    // 初始化AES上下文
    aes_context_t aes_ctx;
    aes_result_t aes_result = aes_init(&aes_ctx, 
                                      conn->encryption_ctx.encryption_key, 
                                      conn->encryption_ctx.key_len, 
                                      conn->encryption_ctx.encryption_iv);
    
    if (aes_result != AES_SUCCESS) {
        log_message(LOG_ERROR, "Failed to initialize AES encryption context");
        return SSH_ERROR_CRYPTO;
    }
    
    // 执行加密
    aes_result = aes_encrypt_cbc(&aes_ctx, plaintext, plaintext_len, ciphertext, ciphertext_len);
    aes_cleanup(&aes_ctx);
    
    if (aes_result != AES_SUCCESS) {
        log_message(LOG_ERROR, "AES encryption failed: %d", aes_result);
        return SSH_ERROR_CRYPTO;
    }

    log_message(LOG_DEBUG, "Encrypted %d bytes of data to %d bytes", plaintext_len, *ciphertext_len);
    return SSH_OK;
}

/**
 * 解密数据
 * @param conn SSH连接上下文
 * @param ciphertext 密文数据
 * @param ciphertext_len 密文长度
 * @param plaintext 明文输出缓冲区
 * @param plaintext_len 明文长度输出
 * @return SSH操作结果
 */
ssh_result_t ssh_decrypt_data(ssh_connection_t *conn, 
                             const unsigned char *ciphertext, 
                             int ciphertext_len,
                             unsigned char *plaintext, 
                             int *plaintext_len) {
    if (!conn || !ciphertext || !plaintext || !plaintext_len) {
        return SSH_ERROR_INVALID_PARAM;
    }

    if (!conn->encryption_ctx.decryption_enabled) {
        return SSH_ERROR_CRYPTO;
    }

    if (ciphertext_len % AES_BLOCK_SIZE != 0) {
        log_message(LOG_ERROR, "Invalid ciphertext length: %d (not multiple of block size)", ciphertext_len);
        return SSH_ERROR_INVALID_PARAM;
    }

    // 初始化AES上下文
    aes_context_t aes_ctx;
    aes_result_t aes_result = aes_init(&aes_ctx, 
                                      conn->encryption_ctx.decryption_key, 
                                      conn->encryption_ctx.key_len, 
                                      conn->encryption_ctx.decryption_iv);
    
    if (aes_result != AES_SUCCESS) {
        log_message(LOG_ERROR, "Failed to initialize AES decryption context");
        return SSH_ERROR_CRYPTO;
    }
    
    // 执行解密
    aes_result = aes_decrypt_cbc(&aes_ctx, ciphertext, ciphertext_len, plaintext, plaintext_len);
    aes_cleanup(&aes_ctx);
    
    if (aes_result != AES_SUCCESS) {
        log_message(LOG_ERROR, "AES decryption failed: %d", aes_result);
        return SSH_ERROR_CRYPTO;
    }

    log_message(LOG_DEBUG, "Decrypted %d bytes of data to %d bytes", ciphertext_len, *plaintext_len);
    return SSH_OK;
}