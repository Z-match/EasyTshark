#pragma once
#include <iostream>
#include "Session.h"
#include <set>
#include "MiscUtil.h"

// IP通信统计信息
struct IPStatsInfo : public BaseDataObject {
    std::string ip;
    std::string location;
    double earliest_time = 0.0;
    double latest_time = 0.0;
    std::set<int> ports;
    std::set<std::string> protocols; // 通信协议集合（包括transProto与appProto）

    // 数据统计
    int total_sent_packets = 0;
    int total_recv_packets = 0;
    int total_sent_bytes = 0;
    int total_recv_bytes = 0;
    int tcp_session_count = 0;
    int udp_session_count = 0;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("ip", rapidjson::Value(ip.c_str(), allocator), allocator);
        obj.AddMember("location", rapidjson::Value(location.c_str(), allocator), allocator);
        std::string s_protocols = MiscUtil::convertSetToString(protocols, ',');
        obj.AddMember("proto", rapidjson::Value(s_protocols.c_str(), allocator), allocator);

        rapidjson::Value portsValue;
        portsValue.SetArray();
        for (auto port : ports) {
            portsValue.PushBack(rapidjson::Value(port), allocator);
        }
        obj.AddMember("ports", portsValue, allocator);

        obj.AddMember("earliest_time", earliest_time, allocator);
        obj.AddMember("latest_time", latest_time, allocator);
        obj.AddMember("total_sent_packets", total_sent_packets, allocator);
        obj.AddMember("total_recv_packets", total_recv_packets, allocator);
        obj.AddMember("total_sent_bytes", total_sent_bytes, allocator);
        obj.AddMember("total_recv_bytes", total_recv_bytes, allocator);
        obj.AddMember("tcp_session_count", tcp_session_count, allocator);
        obj.AddMember("udp_session_count", udp_session_count, allocator);
    }
};

