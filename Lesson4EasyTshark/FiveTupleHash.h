#pragma once
#include "FiveTuple.h"
#include <iostream>

// 定义哈希函数，确保会话对称性
class FiveTupleHash {
public:
    std::size_t operator()(const FiveTuple& tuple) const {
        std::hash<std::string> hashFn;
        std::size_t h1 = hashFn(tuple.src_ip);
        std::size_t h2 = hashFn(tuple.dst_ip);
        std::size_t h3 = std::hash<uint16_t>()(tuple.src_port);
        std::size_t h4 = std::hash<uint16_t>()(tuple.dst_port);

        // 返回源和目的地址/端口的哈希组合，支持对称性
        std::size_t directHash = h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
        std::size_t reverseHash = h2 ^ (h1 << 1) ^ (h4 << 2) ^ (h3 << 3);

        // 确保无论是正向还是反向，都会返回相同的哈希值
        return directHash ^ reverseHash ^ tuple.trans_proto[0];
    }
};

