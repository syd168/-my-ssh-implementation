#include "ssh_protocol.h"
#include <ctype.h>

// 初始化版本信息
ssh_result_t ssh_init_version_info(ssh_version_info_t *version, int is_server) {
    if (!version) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(version, 0, sizeof(ssh_version_info_t));
    
    version->major_version = SSH_VERSION_MAJOR;
    version->minor_version = SSH_VERSION_MINOR;
    strncpy(version->software_name, SSH_SOFTWARE_NAME, sizeof(version->software_name) - 1);
    strncpy(version->software_version, SSH_SOFTWARE_VERSION, sizeof(version->software_version) - 1);
    
    // 添加服务器/客户端标识到注释中
    if (is_server) {
        strncpy(version->comments, "server", sizeof(version->comments) - 1);
    } else {
        strncpy(version->comments, "client", sizeof(version->comments) - 1);
    }
    
    // 构建完整版本字符串
    snprintf(version->full_version, sizeof(version->full_version),
             "SSH-%d.%d-%s_%s %s",
             version->major_version,
             version->minor_version,
             version->software_name,
             version->software_version,
             version->comments);
    
    log_message(LOG_DEBUG, "Initialized SSH version: %s", version->full_version);
    return SSH_OK;
}

// 发送版本字符串
ssh_result_t ssh_send_version_string(int socket_fd, const ssh_version_info_t *version) {
    if (!version) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    // SSH版本字符串必须以\r\n结尾
    char version_line[SSH_MAX_VERSION_LENGTH + 3]; // +2 for \r\n, +1 for \0
    int len = snprintf(version_line, sizeof(version_line), "%s\r\n", version->full_version);
    
    if (len >= (int)sizeof(version_line)) {
        log_message(LOG_ERROR, "Version string too long");
        return SSH_ERROR_INVALID_PARAM;
    }
    
    log_message(LOG_INFO, "Sending SSH version: %s", version->full_version);
    
    ssh_result_t result = send_data(socket_fd, version_line, strlen(version_line));
    if (result != SSH_OK) {
        log_message(LOG_ERROR, "Failed to send version string: %s", ssh_error_string(result));
        return result;
    }
    
    return SSH_OK;
}

// 接收版本字符串
ssh_result_t ssh_receive_version_string(int socket_fd, ssh_version_info_t *version) {
    if (!version) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    char buffer[SSH_MAX_VERSION_LENGTH + 10];
    char version_line[SSH_MAX_VERSION_LENGTH + 10];
    size_t total_received = 0;
    int found_version = 0;
    
    // 循环接收数据直到找到完整的版本行
    while (total_received < sizeof(buffer) - 1 && !found_version) {
        size_t received;
        ssh_result_t result = receive_data(socket_fd, 
                                         buffer + total_received, 
                                         sizeof(buffer) - total_received - 1, 
                                         &received);
        
        if (result != SSH_OK) {
            if (result == SSH_ERROR_TIMEOUT && total_received == 0) {
                // 没有数据可读，继续等待
                continue;
            }
            log_message(LOG_ERROR, "Failed to receive version string: %s", ssh_error_string(result));
            return result;
        }
        
        if (received == 0) {
            // 需要等待更多数据
            if (wait_for_socket_ready(socket_fd, 5, 0) <= 0) {
                log_message(LOG_ERROR, "Timeout waiting for version string");
                return SSH_ERROR_TIMEOUT;
            }
            continue;
        }
        
        total_received += received;
        buffer[total_received] = '\0';
        
        // 查找完整的版本行（以\r\n或\n结尾）
        char *line_end = strstr(buffer, "\r\n");
        if (!line_end) {
            line_end = strstr(buffer, "\n");
        }
        
        if (line_end) {
            size_t line_length = line_end - buffer;
            if (line_length < sizeof(version_line)) {
                strncpy(version_line, buffer, line_length);
                version_line[line_length] = '\0';
                found_version = 1;
            } else {
                log_message(LOG_ERROR, "Version line too long");
                return SSH_ERROR_PROTOCOL;
            }
        }
    }
    
    if (!found_version) {
        log_message(LOG_ERROR, "No complete version line received");
        return SSH_ERROR_PROTOCOL;
    }
    
    log_message(LOG_INFO, "Received SSH version line: %s", version_line);
    
    // 解析版本字符串
    return ssh_parse_version_string(version_line, version);
}

// 解析版本字符串
ssh_result_t ssh_parse_version_string(const char *version_str, ssh_version_info_t *version) {
    if (!version_str || !version) {
        return SSH_ERROR_INVALID_PARAM;
    }
    
    memset(version, 0, sizeof(ssh_version_info_t));
    strncpy(version->full_version, version_str, sizeof(version->full_version) - 1);
    
    // SSH版本字符串格式: SSH-protoversion-softwareversion [comments]
    // 例如: SSH-2.0-MySSH_1.0 server
    
    if (strncmp(version_str, "SSH-", 4) != 0) {
        log_message(LOG_ERROR, "Invalid SSH version string format: %s", version_str);
        return SSH_ERROR_PROTOCOL;
    }
    
    // 解析协议版本
    const char *proto_start = version_str + 4;
    char *dash_pos = strchr(proto_start, '-');
    if (!dash_pos) {
        log_message(LOG_ERROR, "No software version separator found");
        return SSH_ERROR_PROTOCOL;
    }
    
    // 提取协议版本 (如 "2.0")
    char proto_version[16];
    size_t proto_len = dash_pos - proto_start;
    if (proto_len >= sizeof(proto_version)) {
        log_message(LOG_ERROR, "Protocol version too long");
        return SSH_ERROR_PROTOCOL;
    }
    
    strncpy(proto_version, proto_start, proto_len);
    proto_version[proto_len] = '\0';
    
    // 解析主版本号和次版本号
    char *dot_pos = strchr(proto_version, '.');
    if (dot_pos) {
        *dot_pos = '\0';
        version->major_version = atoi(proto_version);
        version->minor_version = atoi(dot_pos + 1);
    } else {
        version->major_version = atoi(proto_version);
        version->minor_version = 0;
    }
    
    // 解析软件版本和注释
    const char *software_start = dash_pos + 1;
    const char *space_pos = strchr(software_start, ' ');
    
    if (space_pos) {
        // 有注释
        size_t software_len = space_pos - software_start;
        if (software_len < sizeof(version->software_name)) {
            strncpy(version->software_name, software_start, software_len);
            version->software_name[software_len] = '\0';
        }
        
        // 提取注释
        strncpy(version->comments, space_pos + 1, sizeof(version->comments) - 1);
    } else {
        // 没有注释
        strncpy(version->software_name, software_start, sizeof(version->software_name) - 1);
    }
    
    // 尝试进一步解析软件名称和版本
    char *underscore_pos = strchr(version->software_name, '_');
    if (underscore_pos) {
        *underscore_pos = '\0';
        strncpy(version->software_version, underscore_pos + 1, sizeof(version->software_version) - 1);
    }
    
    log_message(LOG_INFO, "Parsed SSH version - Protocol: %d.%d, Software: %s %s, Comments: %s",
               version->major_version, version->minor_version,
               version->software_name, version->software_version, version->comments);
    
    return SSH_OK;
}

// 检查版本兼容性
int ssh_is_version_compatible(const ssh_version_info_t *local, const ssh_version_info_t *remote) {
    if (!local || !remote) {
        return 0;
    }
    
    // 检查协议版本兼容性
    // 我们支持SSH-2.0
    if (remote->major_version != 2) {
        log_message(LOG_WARN, "Unsupported SSH protocol version: %d.%d", 
                   remote->major_version, remote->minor_version);
        return 0;
    }
    
    log_message(LOG_INFO, "SSH version compatibility check passed");
    return 1;
}

// 获取协议状态字符串
const char* ssh_protocol_state_string(ssh_protocol_state_t state) {
    switch (state) {
        case SSH_STATE_VERSION_EXCHANGE:
            return "VERSION_EXCHANGE";
        case SSH_STATE_KEY_EXCHANGE:
            return "KEY_EXCHANGE";
        case SSH_STATE_AUTHENTICATION:
            return "AUTHENTICATION";
        case SSH_STATE_CONNECTION:
            return "CONNECTION";
        case SSH_STATE_DISCONNECTED:
            return "DISCONNECTED";
        default:
            return "UNKNOWN";
    }
}
