#ifndef SSH_AES_H
#define SSH_AES_H

#include "../common/common.h"

// AES密钥长度定义
#define AES_128_KEY_SIZE    16
#define AES_256_KEY_SIZE    32
#define AES_BLOCK_SIZE      16
#define AES_IV_SIZE         16

// AES上下文结构
typedef struct {
    unsigned char key[AES_256_KEY_SIZE];    // AES密钥（支持256位）
    unsigned char iv[AES_IV_SIZE];          // 初始化向量
    int key_len;                            // 密钥长度
    int initialized;                        // 初始化标志
} aes_context_t;

// AES操作结果
typedef enum {
    AES_SUCCESS = 0,
    AES_ERROR_INVALID_PARAM = -1,
    AES_ERROR_NOT_INITIALIZED = -2,
    AES_ERROR_ENCRYPT_FAILED = -3,
    AES_ERROR_DECRYPT_FAILED = -4,
    AES_ERROR_INVALID_KEY_SIZE = -5
} aes_result_t;

/**
 * 初始化AES上下文
 * @param ctx AES上下文指针
 * @param key 密钥数据
 * @param key_len 密钥长度（16或32字节）
 * @param iv 初始化向量（16字节）
 * @return AES操作结果
 */
aes_result_t aes_init(aes_context_t *ctx, const unsigned char *key, int key_len, const unsigned char *iv);

/**
 * AES-CBC加密
 * @param ctx AES上下文
 * @param plaintext 明文数据
 * @param plaintext_len 明文长度
 * @param ciphertext 密文输出缓冲区
 * @param ciphertext_len 密文长度输出
 * @return AES操作结果
 */
aes_result_t aes_encrypt_cbc(aes_context_t *ctx, const unsigned char *plaintext, int plaintext_len,
                            unsigned char *ciphertext, int *ciphertext_len);

/**
 * AES-CBC解密
 * @param ctx AES上下文
 * @param ciphertext 密文数据
 * @param ciphertext_len 密文长度
 * @param plaintext 明文输出缓冲区
 * @param plaintext_len 明文长度输出
 * @return AES操作结果
 */
aes_result_t aes_decrypt_cbc(aes_context_t *ctx, const unsigned char *ciphertext, int ciphertext_len,
                            unsigned char *plaintext, int *plaintext_len);

/**
 * 生成随机IV
 * @param iv IV输出缓冲区（16字节）
 * @return AES操作结果
 */
aes_result_t aes_generate_iv(unsigned char *iv);

/**
 * 清理AES上下文（安全清零）
 * @param ctx AES上下文指针
 */
void aes_cleanup(aes_context_t *ctx);

/**
 * PKCS#7填充
 * @param data 数据缓冲区
 * @param data_len 当前数据长度
 * @param block_size 块大小
 * @return 填充后的长度
 */
int aes_pkcs7_pad(unsigned char *data, int data_len, int block_size);

/**
 * PKCS#7去填充
 * @param data 数据缓冲区
 * @param data_len 数据长度
 * @return 去填充后的长度，失败返回-1
 */
int aes_pkcs7_unpad(unsigned char *data, int data_len);

#endif // SSH_AES_H
