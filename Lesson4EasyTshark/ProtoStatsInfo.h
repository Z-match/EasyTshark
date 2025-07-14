#pragma once
#include "Session.h"
#include <iostream>

// 协议统计信息
struct ProtoStatsInfo : public BaseDataObject {

    std::string proto;
    int total_packets = 0;
    int total_bytes = 0;
    int session_count = 0;
    std::string proto_description;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("proto", rapidjson::Value(proto.c_str(), allocator), allocator);
        obj.AddMember("total_packets", total_packets, allocator);
        obj.AddMember("total_bytes", total_bytes, allocator);
        obj.AddMember("session_count", session_count, allocator);
        obj.AddMember("proto_description", rapidjson::Value(proto_description.c_str(), allocator), allocator);
    }
};

