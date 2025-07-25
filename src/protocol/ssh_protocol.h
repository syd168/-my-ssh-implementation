#ifndef SSH_PROTOCOL_H
#define SSH_PROTOCOL_H

#include "../common/common.h"
#include "../network/socket_utils.h"
#include "../crypto/aes.h"

// SSH协议版本定义
#define SSH_VERSION_MAJOR 2
#define SSH_VERSION_MINOR 0
#define SSH_SOFTWARE_NAME "MySSH"
#define SSH_SOFTWARE_VERSION "1.0"
#define SSH_VERSION_STRING "SSH-2.0-MySSH_1.0"

// SSH版本字符串最大长度（RFC 4253）
#define SSH_MAX_VERSION_LENGTH 255
#define SSH_VERSION_BUFFER_SIZE 512  // 增加缓冲区大小避免截断

// SSH协议状态
typedef enum {
    SSH_STATE_VERSION_EXCHANGE = 0,
    SSH_STATE_KEY_EXCHANGE = 1,
    SSH_STATE_AUTHENTICATION = 2,
    SSH_STATE_CONNECTION = 3,
    SSH_STATE_DISCONNECTED = 4,
    SSH_STATE_ENCRYPTED = 5  // 添加加密状态
} ssh_protocol_state_t;


// SSH版本信息结构
typedef struct {
    int major_version;          // 主版本号
    int minor_version;          // 次版本号
    char software_name[64];     // 软件名称
    char software_version[32];  // 软件版本
    char comments[256];         // 注释信息
    char full_version[SSH_VERSION_BUFFER_SIZE]; // 完整版本字符串
} ssh_version_info_t;

// SSH连接上下文
typedef struct {
    int socket_fd;
    ssh_protocol_state_t state;
    ssh_version_info_t local_version;
    ssh_version_info_t remote_version;
    int is_server;
    ssh_encryption_context_t encryption_ctx;  // 添加加密上下文
} ssh_connection_t;

// 函数声明
ssh_result_t ssh_init_version_info(ssh_version_info_t *version, int is_server);
ssh_result_t ssh_send_version_string(int socket_fd, const ssh_version_info_t *version);
ssh_result_t ssh_receive_version_string(int socket_fd, ssh_version_info_t *version);
ssh_result_t ssh_parse_version_string(const char *version_str, ssh_version_info_t *version);
int ssh_is_version_compatible(const ssh_version_info_t *local, const ssh_version_info_t *remote);
const char* ssh_protocol_state_string(ssh_protocol_state_t state);

// 新增加密相关函数声明
ssh_result_t ssh_enable_encryption(ssh_connection_t *conn, 
                                  const unsigned char *encryption_key,
                                  const unsigned char *decryption_key,
                                  int key_len,
                                  const unsigned char *encryption_iv,
                                  const unsigned char *decryption_iv);
ssh_result_t ssh_encrypt_data(ssh_connection_t *conn, 
                             const unsigned char *plaintext, 
                             int plaintext_len,
                             unsigned char *ciphertext, 
                             int *ciphertext_len);
ssh_result_t ssh_decrypt_data(ssh_connection_t *conn, 
                             const unsigned char *ciphertext, 
                             int ciphertext_len,
                             unsigned char *plaintext, 
                             int *plaintext_len);

#endif // SSH_PROTOCOL_H