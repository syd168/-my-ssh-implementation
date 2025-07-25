#ifndef SSH_ENCRYPTION_H
#define SSH_ENCRYPTION_H

#include "../common/common.h"
#include "../crypto/aes.h"
#include "ssh_protocol.h"

// SSH加密上下文定义在 common.h 中

// 加密上下文初始化
ssh_result_t ssh_encryption_context_init(ssh_encryption_context_t *ctx);

// 启用SSH连接的加密功能
ssh_result_t ssh_enable_encryption(ssh_connection_t *conn, 
                                  const unsigned char *encryption_key,
                                  const unsigned char *decryption_key,
                                  int key_len,
                                  const unsigned char *encryption_iv,
                                  const unsigned char *decryption_iv);

// 加密数据
ssh_result_t ssh_encrypt_data(ssh_connection_t *conn, 
                             const unsigned char *plaintext, 
                             int plaintext_len,
                             unsigned char *ciphertext, 
                             int *ciphertext_len);

// 解密数据
ssh_result_t ssh_decrypt_data(ssh_connection_t *conn, 
                             const unsigned char *ciphertext, 
                             int ciphertext_len,
                             unsigned char *plaintext, 
                             int *plaintext_len);

#endif // SSH_ENCRYPTION_H