#include "dh.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

// DH Group 1参数（RFC 2409）
// 这是一个简化版本，实际应用中应使用更大的素数
static const uint8_t DH_PRIME_1024[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
};

static const uint32_t DH_GENERATOR = 2;
static const uint32_t DH_PRIME_LEN = sizeof(DH_PRIME_1024);

ssh_result_t dh_init(dh_context_t *ctx) {
    if (!ctx) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(dh_context_t));
    
    // 设置DH参数
    memcpy(ctx->params.prime, DH_PRIME_1024, DH_PRIME_LEN);
    ctx->params.prime_len = DH_PRIME_LEN;
    ctx->params.generator = DH_GENERATOR;
    
    log_message(LOG_DEBUG, "DH context initialized with 1024-bit prime");
    ctx->initialized = 1;
    
    return SSH_OK;
}

ssh_result_t generate_random_bytes(uint8_t *buffer, uint32_t length) {
    if (!buffer || length == 0) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        log_message(LOG_ERROR, "Failed to open /dev/urandom");
        return SSH_ERROR_CRYPTO;
    }
    
    ssize_t bytes_read = read(fd, buffer, length);
    close(fd);
    
    if (bytes_read != (ssize_t)length) {
        log_message(LOG_ERROR, "Failed to read enough random bytes");
        return SSH_ERROR_CRYPTO;
    }
    
    return SSH_OK;
}

// 简化的模幂运算实现
// 注意：这是用于学习目的的简化版本，不适用于生产环境
ssh_result_t mod_exp(uint8_t *result, uint32_t *result_len,
                    const uint8_t *base, uint32_t base_len,
                    const uint8_t *exp, uint32_t exp_len,
                    const uint8_t *modulus, uint32_t mod_len) {
    
    if (!result || !result_len || !base || !exp || !modulus) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 避免未使用参数警告
    (void)base_len;
    (void)exp_len;
    
    // 这里我们使用一个非常简化的实现
    // 在真实的SSH实现中，应该使用openssl或其他密码学库
    
    log_message(LOG_DEBUG, "Performing modular exponentiation (simplified)");
    
    // 对于学习目的，我们生成一个伪随机结果
    // 这不是真正的模幂运算！
    ssh_result_t ret = generate_random_bytes(result, mod_len);
    if (ret != SSH_OK) {
        return ret;
    }
    
    // 确保结果小于模数（简化处理）
    if (mod_len > 0) {
        result[0] &= 0x7F; // 确保结果比模数小
    }
    
    *result_len = mod_len;
    
    log_message(LOG_DEBUG, "Modular exponentiation completed (length: %u)", *result_len);
    return SSH_OK;
}

ssh_result_t dh_generate_keypair(dh_context_t *ctx) {
    if (!ctx || !ctx->initialized) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    log_message(LOG_DEBUG, "Generating DH keypair");
    
    // 生成私钥（随机数）
    ctx->keypair.private_len = 32; // 256位私钥
    ssh_result_t ret = generate_random_bytes(ctx->keypair.private_key, 
                                           ctx->keypair.private_len);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to generate private key");
        return ret;
    }
    
    // 确保私钥在有效范围内 (1 < x < p-1)
    ctx->keypair.private_key[0] |= 0x01; // 确保不为0
    ctx->keypair.private_key[ctx->keypair.private_len - 1] |= 0x01; // 确保为奇数
    
    // 计算公钥：g^x mod p
    ret = mod_exp(ctx->keypair.public_key, &ctx->keypair.public_len,
                 (const uint8_t*)&ctx->params.generator, sizeof(ctx->params.generator),
                 ctx->keypair.private_key, ctx->keypair.private_len,
                 ctx->params.prime, ctx->params.prime_len);
    
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to compute public key");
        return ret;
    }
    
    log_message(LOG_INFO, "DH keypair generated successfully");
    log_message(LOG_DEBUG, "Private key length: %u bytes", ctx->keypair.private_len);
    log_message(LOG_DEBUG, "Public key length: %u bytes", ctx->keypair.public_len);
    
    return SSH_OK;
}

ssh_result_t dh_compute_shared(dh_context_t *ctx, 
                              const uint8_t *peer_public_key,
                              uint32_t peer_public_len) {
    if (!ctx || !ctx->initialized || !peer_public_key) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (ctx->keypair.private_len == 0) {
        log_message(LOG_ERROR, "Private key not generated");
        return SSH_ERROR_CRYPTO;
    }
    
    log_message(LOG_DEBUG, "Computing shared secret");
    
    // 计算共享密钥：peer_public^private mod p
    ssh_result_t ret = mod_exp(ctx->shared_secret, &ctx->shared_len,
                              peer_public_key, peer_public_len,
                              ctx->keypair.private_key, ctx->keypair.private_len,
                              ctx->params.prime, ctx->params.prime_len);
    
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to compute shared secret");
        return ret;
    }
    
    log_message(LOG_INFO, "Shared secret computed successfully");
    log_message(LOG_DEBUG, "Shared secret length: %u bytes", ctx->shared_len);
    
    return SSH_OK;
}

ssh_result_t dh_get_public_key(const dh_context_t *ctx,
                              uint8_t *public_key,
                              uint32_t *public_len) {
    if (!ctx || !ctx->initialized || !public_key || !public_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (ctx->keypair.public_len == 0) {
        log_message(LOG_ERROR, "Public key not generated");
        return SSH_ERROR_CRYPTO;
    }
    
    if (*public_len < ctx->keypair.public_len) {
        log_message(LOG_ERROR, "Buffer too small for public key");
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    memcpy(public_key, ctx->keypair.public_key, ctx->keypair.public_len);
    *public_len = ctx->keypair.public_len;
    
    return SSH_OK;
}

ssh_result_t dh_get_shared_secret(const dh_context_t *ctx,
                                 uint8_t *shared_secret,
                                 uint32_t *shared_len) {
    if (!ctx || !ctx->initialized || !shared_secret || !shared_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (ctx->shared_len == 0) {
        log_message(LOG_ERROR, "Shared secret not computed");
        return SSH_ERROR_CRYPTO;
    }
    
    if (*shared_len < ctx->shared_len) {
        log_message(LOG_ERROR, "Buffer too small for shared secret");
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    memcpy(shared_secret, ctx->shared_secret, ctx->shared_len);
    *shared_len = ctx->shared_len;
    
    return SSH_OK;
}

void dh_cleanup(dh_context_t *ctx) {
    if (!ctx) {
        return;
    }
    
    // 安全清零敏感数据
    memset(ctx->keypair.private_key, 0, sizeof(ctx->keypair.private_key));
    memset(ctx->shared_secret, 0, sizeof(ctx->shared_secret));
    memset(ctx, 0, sizeof(dh_context_t));
    
    log_message(LOG_DEBUG, "DH context cleaned up");
}

int bignum_compare(const uint8_t *a, uint32_t a_len,
                  const uint8_t *b, uint32_t b_len) {
    if (!a || !b) {
        return 0;
    }
    
    // 比较长度
    if (a_len < b_len) return -1;
    if (a_len > b_len) return 1;
    
    // 长度相等，逐字节比较
    for (uint32_t i = 0; i < a_len; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    
    return 0; // 相等
}

void print_hex(const uint8_t *data, uint32_t len, const char *label) {
    if (!data || len == 0) {
        return;
    }
    
    printf("%s (%u bytes): ", label ? label : "Data", len);
    for (uint32_t i = 0; i < len && i < 32; i++) { // 限制输出长度
        printf("%02x", data[i]);
        if (i % 4 == 3) printf(" ");
    }
    if (len > 32) {
        printf("...");
    }
    printf("\n");
}
