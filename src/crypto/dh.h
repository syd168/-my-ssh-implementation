#ifndef DH_H
#define DH_H

#include "../common/common.h"
#include <stdint.h>

// DH参数定义（简化版本，用于学习）
// 在真实实现中应使用更大的素数和更安全的参数
#define DH_PRIME_BITS 1024
#define DH_MAX_BYTES 128   // 1024位 = 128字节

// Diffie-Hellman参数结构
typedef struct {
    uint8_t prime[DH_MAX_BYTES];      // 大素数 p
    uint32_t prime_len;               // p的长度
    uint32_t generator;               // 生成元 g (通常是2)
} dh_params_t;

// DH密钥对结构
typedef struct {
    uint8_t private_key[DH_MAX_BYTES]; // 私钥 x
    uint32_t private_len;              // 私钥长度
    uint8_t public_key[DH_MAX_BYTES];  // 公钥 g^x mod p
    uint32_t public_len;               // 公钥长度
} dh_keypair_t;

// DH上下文结构
typedef struct {
    dh_params_t params;         // DH参数
    dh_keypair_t keypair;       // 密钥对
    uint8_t shared_secret[DH_MAX_BYTES]; // 共享密钥
    uint32_t shared_len;        // 共享密钥长度
    int initialized;            // 初始化标志
} dh_context_t;

// DH函数声明

/**
 * 初始化DH上下文
 * @param ctx DH上下文
 * @return SSH_OK成功，其他失败
 */
ssh_result_t dh_init(dh_context_t *ctx);

/**
 * 生成DH密钥对
 * @param ctx DH上下文
 * @return SSH_OK成功，其他失败
 */
ssh_result_t dh_generate_keypair(dh_context_t *ctx);

/**
 * 计算共享密钥
 * @param ctx DH上下文
 * @param peer_public_key 对方公钥
 * @param peer_public_len 对方公钥长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t dh_compute_shared(dh_context_t *ctx, 
                              const uint8_t *peer_public_key,
                              uint32_t peer_public_len);

/**
 * 获取公钥
 * @param ctx DH上下文
 * @param public_key 输出公钥缓冲区
 * @param public_len 公钥长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t dh_get_public_key(const dh_context_t *ctx,
                              uint8_t *public_key,
                              uint32_t *public_len);

/**
 * 获取共享密钥
 * @param ctx DH上下文
 * @param shared_secret 输出共享密钥缓冲区
 * @param shared_len 共享密钥长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t dh_get_shared_secret(const dh_context_t *ctx,
                                 uint8_t *shared_secret,
                                 uint32_t *shared_len);

/**
 * 清理DH上下文
 * @param ctx DH上下文
 */
void dh_cleanup(dh_context_t *ctx);

// 辅助函数

/**
 * 生成随机数
 * @param buffer 输出缓冲区
 * @param length 随机数长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t generate_random_bytes(uint8_t *buffer, uint32_t length);

/**
 * 模幂运算: result = base^exp mod modulus
 * 简化实现，用于学习目的
 * @param result 结果缓冲区
 * @param result_len 结果长度
 * @param base 底数
 * @param base_len 底数长度
 * @param exp 指数
 * @param exp_len 指数长度
 * @param modulus 模数
 * @param mod_len 模数长度
 * @return SSH_OK成功，其他失败
 */
ssh_result_t mod_exp(uint8_t *result, uint32_t *result_len,
                    const uint8_t *base, uint32_t base_len,
                    const uint8_t *exp, uint32_t exp_len,
                    const uint8_t *modulus, uint32_t mod_len);

/**
 * 大数比较
 * @param a 数值A
 * @param a_len A的长度
 * @param b 数值B  
 * @param b_len B的长度
 * @return -1: a<b, 0: a==b, 1: a>b
 */
int bignum_compare(const uint8_t *a, uint32_t a_len,
                  const uint8_t *b, uint32_t b_len);

/**
 * 打印十六进制数据（调试用）
 * @param data 数据
 * @param len 长度
 * @param label 标签
 */
void print_hex(const uint8_t *data, uint32_t len, const char *label);

#endif // DH_H
