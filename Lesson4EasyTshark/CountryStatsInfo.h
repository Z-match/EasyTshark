#pragma once
#include "Session.h"

// 国家统计信息结构体
struct CountryStatsInfo : public BaseDataObject {
    std::string country;
    int sent_packets = 0;
    int sent_bytes = 0;
    int recv_packets = 0;
    int recv_bytes = 0;
    int ip_count = 0;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("country", rapidjson::Value(country.c_str(), allocator), allocator);
        obj.AddMember("sent_packets", sent_packets, allocator);
        obj.AddMember("sent_bytes", sent_bytes, allocator);
        obj.AddMember("recv_packets", recv_packets, allocator);
        obj.AddMember("recv_bytes", recv_bytes, allocator);
        obj.AddMember("ip_count", ip_count, allocator);
    }
};


