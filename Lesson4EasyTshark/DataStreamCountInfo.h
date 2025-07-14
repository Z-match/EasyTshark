#pragma once
#include "Session.h"

// 数据流统计信息
class DataStreamCountInfo : public BaseDataObject {
public:
    uint32_t totalPacketCount = 0;
    std::string node0;
    uint32_t node0PacketCount = 0;
    uint32_t node0BytesCount = 0;
    std::string node1;
    uint32_t node1PacketCount = 0;
    uint32_t node1BytesCount = 0;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("totalPacketCount", totalPacketCount, allocator);

        obj.AddMember("node0", rapidjson::Value(node0.c_str(), allocator), allocator);
        obj.AddMember("node0PacketCount", node0PacketCount, allocator);
        obj.AddMember("node0BytesCount", node0BytesCount, allocator);

        obj.AddMember("node1", rapidjson::Value(node1.c_str(), allocator), allocator);
        obj.AddMember("node1PacketCount", node1PacketCount, allocator);
        obj.AddMember("node1BytesCount", node1BytesCount, allocator);
    }
};

