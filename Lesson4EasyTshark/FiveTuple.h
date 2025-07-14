#pragma once
#include <iostream>

// 定义五元组
class FiveTuple {
public:
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string trans_proto;

    // 重载比较操作符，用于 unordered_map 的键比较，确保会话对称性
    bool operator==(const FiveTuple& other) const {
        return ((src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port && dst_port == other.dst_port)
            || (src_ip == other.dst_ip && dst_ip == other.src_ip && src_port == other.dst_port && dst_port == other.src_port))
            && trans_proto == other.trans_proto;

    }
};

