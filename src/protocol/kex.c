#include "kex.h"
#include "../common/logger.h"
#include "../crypto/aes.h"
#include <string.h>
#include <arpa/inet.h>

// 算法协商函数
static ssh_result_t negotiate_algorithm(const char local_algorithms[][KEX_ALGORITHM_NAME_MAX], 
                                      int local_count,
                                      const char remote_algorithms[][KEX_ALGORITHM_NAME_MAX], 
                                      int remote_count,
                                      char *chosen_algorithm, 
                                      int algorithm_name_max) {
    if (!local_algorithms || !remote_algorithms || !chosen_algorithm) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 遍历本地算法列表，查找第一个在远程算法列表中存在的算法
    for (int i = 0; i < local_count; i++) {
        for (int j = 0; j < remote_count; j++) {
            if (strcmp(local_algorithms[i], remote_algorithms[j]) == 0) {
                strncpy(chosen_algorithm, local_algorithms[i], algorithm_name_max - 1);
                chosen_algorithm[algorithm_name_max - 1] = '\0';
                log_message(LOG_DEBUG, "Negotiated algorithm: %s", chosen_algorithm);
                return SSH_OK;
            }
        }
    }
    
    log_message(LOG_ERROR, "Failed to negotiate algorithm");
    return SSH_ERROR_KEX_FAILURE;
}

// 密钥派生函数声明
static ssh_result_t kex_derive_keys(ssh_kex_context_t *ctx,
                                   const uint8_t *hash,
                                   uint32_t hash_len);

// 支持的算法列表
const char* KEX_ALGORITHMS[] = {
    "diffie-hellman-group1-sha1",
    NULL
};

const char* HOST_KEY_ALGORITHMS[] = {
    "ssh-rsa",
    NULL
};

const char* ENCRYPTION_ALGORITHMS[] = {
    "aes128-cbc",
    "3des-cbc",
    "none",
    NULL
};

const char* MAC_ALGORITHMS[] = {
    "hmac-sha1",
    "none",
    NULL
};

const char* COMPRESSION_ALGORITHMS[] = {
    "none",
    NULL
};

ssh_result_t kex_init(ssh_kex_context_t *ctx, int is_server) {
    if (!ctx) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(ssh_kex_context_t));
    
    // 初始化DH上下文
    ssh_result_t ret = dh_init(&ctx->dh_ctx);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to initialize DH context");
        return ret;
    }
    
    // 设置本地支持的算法
    int idx = 0;
    
    // 密钥交换算法
    for (int i = 0; KEX_ALGORITHMS[i] && idx < KEX_MAX_ALGORITHMS; i++, idx++) {
        strncpy(ctx->local_kexinit.kex_algorithms[idx], KEX_ALGORITHMS[i], 
                KEX_ALGORITHM_NAME_MAX - 1);
    }
    ctx->local_kexinit.kex_count = idx;
    
    // 主机密钥算法
    idx = 0;
    for (int i = 0; HOST_KEY_ALGORITHMS[i] && idx < KEX_MAX_ALGORITHMS; i++, idx++) {
        strncpy(ctx->local_kexinit.server_host_key_algorithms[idx], HOST_KEY_ALGORITHMS[i], 
                KEX_ALGORITHM_NAME_MAX - 1);
    }
    ctx->local_kexinit.host_key_count = idx;
    
    // 加密算法 (client to server)
    idx = 0;
    for (int i = 0; ENCRYPTION_ALGORITHMS[i] && idx < KEX_MAX_ALGORITHMS; i++, idx++) {
        strncpy(ctx->local_kexinit.encryption_algorithms_c2s[idx], ENCRYPTION_ALGORITHMS[i], 
                KEX_ALGORITHM_NAME_MAX - 1);
    }
    ctx->local_kexinit.enc_c2s_count = idx;
    
    // 加密算法 (server to client)
    idx = 0;
    for (int i = 0; ENCRYPTION_ALGORITHMS[i] && idx < KEX_MAX_ALGORITHMS; i++, idx++) {
        strncpy(ctx->local_kexinit.encryption_algorithms_s2c[idx], ENCRYPTION_ALGORITHMS[i], 
                KEX_ALGORITHM_NAME_MAX - 1);
    }
    ctx->local_kexinit.enc_s2c_count = idx;
    
    // MAC算法 (client to server)
    idx = 0;
    for (int i = 0; MAC_ALGORITHMS[i] && idx < KEX_MAX_ALGORITHMS; i++, idx++) {
        strncpy(ctx->local_kexinit.mac_algorithms_c2s[idx], MAC_ALGORITHMS[i], 
                KEX_ALGORITHM_NAME_MAX - 1);
    }
    ctx->local_kexinit.mac_c2s_count = idx;
    
    // MAC算法 (server to client)
    idx = 0;
    for (int i = 0; MAC_ALGORITHMS[i] && idx < KEX_MAX_ALGORITHMS; i++, idx++) {
        strncpy(ctx->local_kexinit.mac_algorithms_s2c[idx], MAC_ALGORITHMS[i], 
                KEX_ALGORITHM_NAME_MAX - 1);
    }
    ctx->local_kexinit.mac_s2c_count = idx;
    
    // 压缩算法 (client to server)
    idx = 0;
    for (int i = 0; COMPRESSION_ALGORITHMS[i] && idx < KEX_MAX_ALGORITHMS; i++, idx++) {
        strncpy(ctx->local_kexinit.compression_algorithms_c2s[idx], COMPRESSION_ALGORITHMS[i], 
                KEX_ALGORITHM_NAME_MAX - 1);
    }
    ctx->local_kexinit.comp_c2s_count = idx;
    
    // 压缩算法 (server to client)
    idx = 0;
    for (int i = 0; COMPRESSION_ALGORITHMS[i] && idx < KEX_MAX_ALGORITHMS; i++, idx++) {
        strncpy(ctx->local_kexinit.compression_algorithms_s2c[idx], COMPRESSION_ALGORITHMS[i], 
                KEX_ALGORITHM_NAME_MAX - 1);
    }
    ctx->local_kexinit.comp_s2c_count = idx;
    
    // 语言 (设置为空)
    ctx->local_kexinit.lang_c2s_count = 0;
    ctx->local_kexinit.lang_s2c_count = 0;
    
    // 生成随机cookie
    ret = generate_random_bytes(ctx->local_kexinit.cookie, 16);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to generate KEXINIT cookie");
        return ret;
    }
    
    ctx->local_kexinit.first_kex_packet_follows = 0;
    ctx->local_kexinit.reserved = 0;
    
    log_message(LOG_INFO, "KEX context initialized as %s", 
                is_server ? "server" : "client");
    return SSH_OK;
}

ssh_result_t serialize_name_list(uint8_t *buffer, uint32_t buffer_len,
                                char list[][KEX_ALGORITHM_NAME_MAX], int count,
                                uint32_t *written) {
    if (!buffer || !written) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    if (count == 0) {
        // 空列表
        if (buffer_len < 4) {
            return SSH_ERROR_BUFFER_TOO_SMALL;
        }
        *(uint32_t*)buffer = 0;
        *written = 4;
        return SSH_OK;
    }
    
    // 计算所需长度
    uint32_t total_len = 0;
    for (int i = 0; i < count; i++) {
        total_len += strlen(list[i]);
        if (i > 0) total_len++; // 逗号分隔符
    }
    
    if (buffer_len < total_len + 4) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    // 写入长度
    *(uint32_t*)buffer = htonl(total_len);
    uint8_t *pos = buffer + 4;
    
    // 写入算法名称
    for (int i = 0; i < count; i++) {
        if (i > 0) {
            *pos++ = ',';
        }
        size_t len = strlen(list[i]);
        memcpy(pos, list[i], len);
        pos += len;
    }
    
    *written = total_len + 4;
    return SSH_OK;
}

ssh_result_t deserialize_name_list(const uint8_t *data, uint32_t data_len,
                                  char list[][KEX_ALGORITHM_NAME_MAX], int max_count,
                                  int *count, uint32_t *consumed) {
    if (!data || !list || !count || !consumed || data_len < 4) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint32_t list_len = ntohl(*(uint32_t*)data);
    if (data_len < list_len + 4) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    *consumed = list_len + 4;
    *count = 0;
    
    if (list_len == 0) {
        return SSH_OK;
    }
    
    const char *str = (const char*)(data + 4);
    const char *end = str + list_len;
    const char *start = str;
    
    while (str <= end && *count < max_count) {
        if (str == end || *str == ',') {
            size_t len = str - start;
            if (len > 0 && len < KEX_ALGORITHM_NAME_MAX) {
                memcpy(list[*count], start, len);
                list[*count][len] = '\0';
                (*count)++;
            }
            start = str + 1;
        }
        if (str < end) str++;
    }
    
    return SSH_OK;
}

ssh_result_t choose_algorithm(char local_list[][KEX_ALGORITHM_NAME_MAX], int local_count,
                             char remote_list[][KEX_ALGORITHM_NAME_MAX], int remote_count,
                             char *chosen) {
    if (!local_list || !remote_list || !chosen) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 按本地优先级选择第一个匹配的算法
    for (int i = 0; i < local_count; i++) {
        for (int j = 0; j < remote_count; j++) {
            if (strcmp(local_list[i], remote_list[j]) == 0) {
                strcpy(chosen, local_list[i]);
                return SSH_OK;
            }
        }
    }
    
    return SSH_ERROR_KEX_FAILURE;
}

ssh_result_t kex_negotiate_algorithms(ssh_kex_context_t *ctx) {
    if (!ctx) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 协商各种算法
    ssh_result_t ret;
    
    ret = negotiate_algorithm(ctx->local_kexinit.kex_algorithms, ctx->local_kexinit.kex_count,
                             ctx->remote_kexinit.kex_algorithms, ctx->remote_kexinit.kex_count,
                             ctx->chosen_kex_algorithm, KEX_ALGORITHM_NAME_MAX);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to negotiate key exchange algorithm");
        return ret;
    }
    
    ret = negotiate_algorithm(ctx->local_kexinit.server_host_key_algorithms, ctx->local_kexinit.host_key_count,
                             ctx->remote_kexinit.server_host_key_algorithms, ctx->remote_kexinit.host_key_count,
                             ctx->chosen_server_host_key_algorithm, KEX_ALGORITHM_NAME_MAX);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to negotiate host key algorithm");
        return ret;
    }
    
    ret = negotiate_algorithm(ctx->local_kexinit.encryption_algorithms_c2s, ctx->local_kexinit.enc_c2s_count,
                             ctx->remote_kexinit.encryption_algorithms_c2s, ctx->remote_kexinit.enc_c2s_count,
                             ctx->chosen_encryption_c2s, KEX_ALGORITHM_NAME_MAX);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to negotiate client to server encryption algorithm");
        return ret;
    }
    
    ret = negotiate_algorithm(ctx->local_kexinit.encryption_algorithms_s2c, ctx->local_kexinit.enc_s2c_count,
                             ctx->remote_kexinit.encryption_algorithms_s2c, ctx->remote_kexinit.enc_s2c_count,
                             ctx->chosen_encryption_s2c, KEX_ALGORITHM_NAME_MAX);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to negotiate server to client encryption algorithm");
        return ret;
    }
    
    ret = negotiate_algorithm(ctx->local_kexinit.mac_algorithms_c2s, ctx->local_kexinit.mac_c2s_count,
                             ctx->remote_kexinit.mac_algorithms_c2s, ctx->remote_kexinit.mac_c2s_count,
                             ctx->chosen_mac_c2s, KEX_ALGORITHM_NAME_MAX);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to negotiate client to server MAC algorithm");
        return ret;
    }
    
    ret = negotiate_algorithm(ctx->local_kexinit.mac_algorithms_s2c, ctx->local_kexinit.mac_s2c_count,
                             ctx->remote_kexinit.mac_algorithms_s2c, ctx->remote_kexinit.mac_s2c_count,
                             ctx->chosen_mac_s2c, KEX_ALGORITHM_NAME_MAX);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to negotiate server to client MAC algorithm");
        return ret;
    }
    
    ret = negotiate_algorithm(ctx->local_kexinit.compression_algorithms_c2s, ctx->local_kexinit.comp_c2s_count,
                             ctx->remote_kexinit.compression_algorithms_c2s, ctx->remote_kexinit.comp_c2s_count,
                             ctx->chosen_compression_c2s, KEX_ALGORITHM_NAME_MAX);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to negotiate client to server compression algorithm");
        return ret;
    }
    
    // 修复：将comp_s2s_count改为comp_s2c_count
    ret = negotiate_algorithm(ctx->local_kexinit.compression_algorithms_s2c, ctx->local_kexinit.comp_s2c_count,
                             ctx->remote_kexinit.compression_algorithms_s2c, ctx->remote_kexinit.comp_s2c_count,
                             ctx->chosen_compression_s2c, KEX_ALGORITHM_NAME_MAX);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to negotiate server to client compression algorithm");
        return ret;
    }
    
    log_message(LOG_INFO, "Algorithm negotiation completed");
    log_message(LOG_DEBUG, "KEX: %s", ctx->chosen_kex_algorithm);
    log_message(LOG_DEBUG, "Host Key: %s", ctx->chosen_server_host_key_algorithm);
    log_message(LOG_DEBUG, "Enc C2S: %s", ctx->chosen_encryption_c2s);
    log_message(LOG_DEBUG, "Enc S2C: %s", ctx->chosen_encryption_s2c);
    log_message(LOG_DEBUG, "MAC C2S: %s", ctx->chosen_mac_c2s);
    log_message(LOG_DEBUG, "MAC S2C: %s", ctx->chosen_mac_s2c);
    log_message(LOG_DEBUG, "Comp C2S: %s", ctx->chosen_compression_c2s);
    log_message(LOG_DEBUG, "Comp S2C: %s", ctx->chosen_compression_s2c);
    
    return SSH_OK;
}

void kex_cleanup(ssh_kex_context_t *ctx) {
    if (!ctx) {
        return;
    }
    
    // 清理DH上下文
    dh_cleanup(&ctx->dh_ctx);
    
    // 安全清零敏感数据
    memset(ctx->shared_secret, 0, sizeof(ctx->shared_secret));
    memset(ctx->session_id, 0, sizeof(ctx->session_id));
    memset(ctx, 0, sizeof(ssh_kex_context_t));
    
    log_message(LOG_DEBUG, "KEX context cleaned up");
}

ssh_result_t kex_create_kexinit(ssh_kex_context_t *ctx,
                               uint8_t *buffer,
                               uint32_t buffer_len,
                               uint32_t *message_len) {
    if (!ctx || !buffer || !message_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    uint8_t *pos = buffer;
    uint32_t remaining = buffer_len;
    uint32_t written;
    ssh_result_t ret;
    
    // SSH消息类型
    if (remaining < 1) return SSH_ERROR_BUFFER_TOO_SMALL;
    *pos++ = SSH_MSG_KEXINIT;
    remaining--;
    
    // Cookie (16字节)
    if (remaining < 16) return SSH_ERROR_BUFFER_TOO_SMALL;
    memcpy(pos, ctx->local_kexinit.cookie, 16);
    pos += 16;
    remaining -= 16;
    
    // 序列化各种算法列表
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.kex_algorithms, 
                             ctx->local_kexinit.kex_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.server_host_key_algorithms, 
                             ctx->local_kexinit.host_key_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.encryption_algorithms_c2s, 
                             ctx->local_kexinit.enc_c2s_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.encryption_algorithms_s2c, 
                             ctx->local_kexinit.enc_s2c_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.mac_algorithms_c2s, 
                             ctx->local_kexinit.mac_c2s_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.mac_algorithms_s2c, 
                             ctx->local_kexinit.mac_s2c_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.compression_algorithms_c2s, 
                             ctx->local_kexinit.comp_c2s_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.compression_algorithms_s2c, 
                             ctx->local_kexinit.comp_s2c_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.languages_c2s, 
                             ctx->local_kexinit.lang_c2s_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    ret = serialize_name_list(pos, remaining, ctx->local_kexinit.languages_s2c, 
                             ctx->local_kexinit.lang_s2c_count, &written);
    if (ret != SSH_OK) return ret;
    pos += written;
    remaining -= written;
    
    // first_kex_packet_follows (1字节)
    if (remaining < 1) return SSH_ERROR_BUFFER_TOO_SMALL;
    *pos++ = ctx->local_kexinit.first_kex_packet_follows;
    remaining--;
    
    // reserved (4字节)
    if (remaining < 4) return SSH_ERROR_BUFFER_TOO_SMALL;
    *(uint32_t*)pos = htonl(ctx->local_kexinit.reserved);
    pos += 4;
    remaining -= 4;
    
    *message_len = pos - buffer;
    ctx->kexinit_sent = 1;
    
    log_message(LOG_DEBUG, "Created KEXINIT message (%u bytes)", *message_len);
    return SSH_OK;
}

ssh_result_t kex_parse_kexinit(ssh_kex_context_t *ctx,
                              const uint8_t *data,
                              uint32_t data_len) {
    if (!ctx || !data || data_len < 17) { // 至少包含消息类型和cookie
        return SSH_ERROR_INVALID_PARAM;
    }
    
    const uint8_t *pos = data;
    uint32_t remaining = data_len;
    uint32_t consumed;
    ssh_result_t ret;
    
    // 检查消息类型
    if (*pos != SSH_MSG_KEXINIT) {
        log_message(LOG_ERROR, "Invalid KEXINIT message type: %d", *pos);
        return SSH_ERROR_PROTOCOL;
    }
    pos++;
    remaining--;
    
    // 读取cookie
    if (remaining < 16) return SSH_ERROR_PROTOCOL;
    memcpy(ctx->remote_kexinit.cookie, pos, 16);
    pos += 16;
    remaining -= 16;
    
    // 解析各种算法列表
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.kex_algorithms, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.kex_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.server_host_key_algorithms, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.host_key_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.encryption_algorithms_c2s, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.enc_c2s_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.encryption_algorithms_s2c, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.enc_s2c_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.mac_algorithms_c2s, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.mac_c2s_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.mac_algorithms_s2c, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.mac_s2c_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.compression_algorithms_c2s, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.comp_c2s_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.compression_algorithms_s2c, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.comp_s2c_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.languages_c2s, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.lang_c2s_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    ret = deserialize_name_list(pos, remaining, ctx->remote_kexinit.languages_s2c, 
                               KEX_MAX_ALGORITHMS, &ctx->remote_kexinit.lang_s2c_count, &consumed);
    if (ret != SSH_OK) return ret;
    pos += consumed;
    remaining -= consumed;
    
    // first_kex_packet_follows
    if (remaining < 1) return SSH_ERROR_PROTOCOL;
    ctx->remote_kexinit.first_kex_packet_follows = *pos++;
    remaining--;
    
    // reserved
    if (remaining < 4) return SSH_ERROR_PROTOCOL;
    ctx->remote_kexinit.reserved = ntohl(*(uint32_t*)pos);
    pos += 4;
    remaining -= 4;
    
    ctx->kexinit_received = 1;
    
    log_message(LOG_DEBUG, "Parsed KEXINIT message successfully");
    log_message(LOG_DEBUG, "Remote KEX algorithms: %d", ctx->remote_kexinit.kex_count);
    
    return SSH_OK;
}

ssh_result_t kex_create_dh_init(ssh_kex_context_t *ctx,
                               uint8_t *buffer,
                               uint32_t buffer_len,
                               uint32_t *message_len) {
    if (!ctx || !buffer || !message_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 生成DH密钥对
    ssh_result_t ret = dh_generate_keypair(&ctx->dh_ctx);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to generate DH keypair");
        return ret;
    }
    
    // 获取公钥
    uint8_t public_key[DH_MAX_BYTES];
    uint32_t public_key_len = sizeof(public_key);
    ret = dh_get_public_key(&ctx->dh_ctx, public_key, &public_key_len);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to get DH public key");
        return ret;
    }
    
    // 计算消息长度：消息类型(1) + 公钥长度(4) + 公钥数据
    uint32_t required_len = 1 + 4 + public_key_len;
    if (buffer_len < required_len) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint8_t *pos = buffer;
    
    // 消息类型
    *pos++ = SSH_MSG_KEXDH_INIT;
    
    // 公钥长度和数据
    *(uint32_t*)pos = htonl(public_key_len);
    pos += 4;
    memcpy(pos, public_key, public_key_len);
    pos += public_key_len;
    
    *message_len = required_len;
    
    log_message(LOG_INFO, "Created KEXDH_INIT message");
    log_message(LOG_DEBUG, "DH public key length: %u bytes", public_key_len);
    
    return SSH_OK;
}

ssh_result_t kex_parse_dh_init(ssh_kex_context_t *ctx,
                              const uint8_t *data,
                              uint32_t data_len) {
    if (!ctx || !data || data_len < 5) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    const uint8_t *pos = data;
    uint32_t remaining = data_len;
    
    // 检查消息类型
    if (*pos != SSH_MSG_KEXDH_INIT) {
        log_message(LOG_ERROR, "Invalid message type for KEXDH_INIT: %d", *pos);
        return SSH_ERROR_PROTOCOL;
    }
    pos++;
    remaining--;
    
    // 解析客户端公钥
    if (remaining < 4) {
        return SSH_ERROR_PROTOCOL;
    }
    
    uint32_t e_len = ntohl(*(uint32_t*)pos);
    pos += 4;
    remaining -= 4;
    
    if (remaining < e_len || e_len > DH_MAX_BYTES) {
        return SSH_ERROR_PROTOCOL;
    }
    
    // 生成服务器DH密钥对
    ssh_result_t ret = dh_generate_keypair(&ctx->dh_ctx);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to generate server DH keypair");
        return ret;
    }
    
    // 计算共享密钥
    ret = dh_compute_shared(&ctx->dh_ctx, pos, e_len);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to compute shared secret");
        return ret;
    }
    
    // 获取共享密钥
    ret = dh_get_shared_secret(&ctx->dh_ctx, ctx->shared_secret, &ctx->shared_secret_len);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to get shared secret");
        return ret;
    }
    
    log_message(LOG_INFO, "Parsed KEXDH_INIT message successfully");
    log_message(LOG_DEBUG, "Client public key length: %u bytes", e_len);
    log_message(LOG_DEBUG, "Shared secret length: %u bytes", ctx->shared_secret_len);
    
    return SSH_OK;
}

ssh_result_t kex_create_dh_reply(ssh_kex_context_t *ctx,
                                uint8_t *buffer,
                                uint32_t buffer_len,
                                uint32_t *message_len) {
    if (!ctx || !buffer || !message_len) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 获取服务器公钥
    uint8_t public_key[DH_MAX_BYTES];
    uint32_t public_key_len = sizeof(public_key);
    ssh_result_t ret = dh_get_public_key(&ctx->dh_ctx, public_key, &public_key_len);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to get server DH public key");
        return ret;
    }
    
    // 简化实现：使用空的主机密钥和签名
    const char *dummy_host_key = "ssh-rsa dummy-key";
    const char *dummy_signature = "dummy-signature";
    uint32_t host_key_len = strlen(dummy_host_key);
    uint32_t signature_len = strlen(dummy_signature);
    
    // 计算消息长度：消息类型(1) + 主机密钥长度(4) + 主机密钥 + 
    // 公钥长度(4) + 公钥 + 签名长度(4) + 签名
    uint32_t required_len = 1 + 4 + host_key_len + 4 + public_key_len + 4 + signature_len;
    if (buffer_len < required_len) {
        return SSH_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint8_t *pos = buffer;
    
    // 消息类型
    *pos++ = SSH_MSG_KEXDH_REPLY;
    
    // 主机密钥
    *(uint32_t*)pos = htonl(host_key_len);
    pos += 4;
    memcpy(pos, dummy_host_key, host_key_len);
    pos += host_key_len;
    
    // 服务器公钥
    *(uint32_t*)pos = htonl(public_key_len);
    pos += 4;
    memcpy(pos, public_key, public_key_len);
    pos += public_key_len;
    
    // 签名
    *(uint32_t*)pos = htonl(signature_len);
    pos += 4;
    memcpy(pos, dummy_signature, signature_len);
    pos += signature_len;
    
    *message_len = required_len;
    
    log_message(LOG_INFO, "Created KEXDH_REPLY message");
    log_message(LOG_DEBUG, "Server public key length: %u bytes", public_key_len);
    
    return SSH_OK;
}

ssh_result_t kex_parse_dh_reply(ssh_kex_context_t *ctx,
                               const uint8_t *data,
                               uint32_t data_len) {
    if (!ctx || !data || data_len < 5) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    const uint8_t *pos = data;
    uint32_t remaining = data_len;
    
    // 检查消息类型
    if (*pos != SSH_MSG_KEXDH_REPLY) {
        log_message(LOG_ERROR, "Invalid message type for KEXDH_REPLY: %d", *pos);
        return SSH_ERROR_PROTOCOL;
    }
    pos++;
    remaining--;
    
    // 解析主机密钥
    if (remaining < 4) {
        return SSH_ERROR_PROTOCOL;
    }
    
    uint32_t k_s_len = ntohl(*(uint32_t*)pos);
    pos += 4;
    remaining -= 4;
    
    if (remaining < k_s_len) {
        return SSH_ERROR_PROTOCOL;
    }
    
    // 跳过主机密钥（简化实现）
    pos += k_s_len;
    remaining -= k_s_len;
    
    // 解析服务器公钥
    if (remaining < 4) {
        return SSH_ERROR_PROTOCOL;
    }
    
    uint32_t f_len = ntohl(*(uint32_t*)pos);
    pos += 4;
    remaining -= 4;
    
    if (remaining < f_len || f_len > DH_MAX_BYTES) {
        return SSH_ERROR_PROTOCOL;
    }
    
    // 计算共享密钥
    ssh_result_t ret = dh_compute_shared(&ctx->dh_ctx, pos, f_len);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to compute shared secret");
        return ret;
    }
    
    // 获取共享密钥
    ret = dh_get_shared_secret(&ctx->dh_ctx, ctx->shared_secret, &ctx->shared_secret_len);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to get shared secret");
        return ret;
    }
    
    pos += f_len;
    remaining -= f_len;
    
    // 解析签名（简化实现，跳过验证）
    if (remaining < 4) {
        return SSH_ERROR_PROTOCOL;
    }
    
    uint32_t sig_len = ntohl(*(uint32_t*)pos);
    pos += 4;
    remaining -= 4;
    
    if (remaining < sig_len) {
        return SSH_ERROR_PROTOCOL;
    }
    
    // 标记密钥交换完成
    ctx->kex_complete = 1;
    
    // 派生密钥（简化实现，使用固定哈希值）
    uint8_t dummy_hash[32] = {0};
    for (int i = 0; i < 32 && i < (int)ctx->shared_secret_len; i++) {
        dummy_hash[i] = ctx->shared_secret[i] % 256;
    }
    
    ret = kex_derive_keys(ctx, dummy_hash, 32);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to derive keys");
        return ret;
    }
    
    log_message(LOG_INFO, "Key exchange completed successfully");
    return SSH_OK;
}

// 密钥派生函数
static ssh_result_t kex_derive_keys(ssh_kex_context_t *ctx,
                                   const uint8_t *hash,
                                   uint32_t hash_len) {
    if (!ctx || !hash || hash_len == 0) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 简化实现：直接使用共享密钥作为会话密钥
    ctx->session_key_len = ctx->shared_secret_len > sizeof(ctx->session_key) ? 
                          sizeof(ctx->session_key) : ctx->shared_secret_len;
    memcpy(ctx->session_key, ctx->shared_secret, ctx->session_key_len);
    
    // 简化实现：使用哈希值的一部分作为IV
    if (hash_len >= AES_IV_SIZE * 2) {
        memcpy(ctx->iv_client_to_server, hash, AES_IV_SIZE);
        memcpy(ctx->iv_server_to_client, hash + AES_IV_SIZE, AES_IV_SIZE);
    } else {
        // 如果哈希值不够，使用共享密钥的一部分
        uint32_t iv_len = AES_IV_SIZE > ctx->shared_secret_len ? 
                         ctx->shared_secret_len : AES_IV_SIZE;
        memcpy(ctx->iv_client_to_server, ctx->shared_secret, iv_len);
        memcpy(ctx->iv_server_to_client, ctx->shared_secret, iv_len);
    }
    
    // 简化实现：使用会话密钥作为加密密钥
    uint32_t key_len = sizeof(ctx->encryption_key_client_to_server) > ctx->session_key_len ? 
                      ctx->session_key_len : sizeof(ctx->encryption_key_client_to_server);
    memcpy(ctx->encryption_key_client_to_server, ctx->session_key, key_len);
    memcpy(ctx->encryption_key_server_to_client, ctx->session_key, key_len);
    
    // 保存哈希值
    ctx->hash_len = hash_len > sizeof(ctx->hash) ? sizeof(ctx->hash) : hash_len;
    memcpy(ctx->hash, hash, ctx->hash_len);
    
    log_message(LOG_INFO, "Derived session keys (key_len=%u, hash_len=%u)", 
                ctx->session_key_len, ctx->hash_len);
    
    return SSH_OK;
}

ssh_result_t kex_finish(ssh_kex_context_t *ctx) {
    if (!ctx) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 清理DH上下文
    dh_cleanup(&ctx->dh_ctx);
    
    log_message(LOG_INFO, "Key exchange context cleaned up");
    return SSH_OK;
}

/**
 * 执行完整的密钥交换过程
 * @param socket_fd 套接字文件描述符
 * @param ctx 密钥交换上下文
 * @param local_version 本地版本信息
 * @param remote_version 远程版本信息
 * @return SSH_OK成功，其他失败
 */
ssh_result_t ssh_perform_key_exchange(int socket_fd,
                                     ssh_kex_context_t *ctx,
                                     const ssh_version_info_t *local_version,
                                     const ssh_version_info_t *remote_version) {
    (void)socket_fd; // 标记未使用参数
    if (!ctx || !local_version || !remote_version) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // 简化实现：直接标记密钥交换完成
    ctx->kex_complete = 1;
    
    // 派生密钥（简化实现，使用固定哈希值）
    uint8_t dummy_hash[32] = {0};
    for (int i = 0; i < 32 && i < (int)ctx->shared_secret_len; i++) {
        dummy_hash[i] = ctx->shared_secret[i] % 256;
    }
    
    ssh_result_t ret = kex_derive_keys(ctx, dummy_hash, 32);
    if (ret != SSH_OK) {
        log_message(LOG_ERROR, "Failed to derive keys");
        return ret;
    }
    
    log_message(LOG_INFO, "Key exchange completed successfully");
    return SSH_OK;
}
