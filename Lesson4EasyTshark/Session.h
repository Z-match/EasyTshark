#pragma once
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include <iostream>

class BaseDataObject {
public:
    // 将对象转换为JSON Value，用于转换为JSON格式输出
    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const = 0;
};

// 会话信息
class Session : public BaseDataObject {
public:
    uint32_t session_id;
    std::string ip1;
    uint16_t ip1_port;
    std::string ip1_location;
    std::string ip2;
    uint16_t ip2_port;
    std::string ip2_location;
    std::string trans_proto;
    std::string app_proto;
    double start_time;
    double end_time;
    uint32_t ip1_send_packets_count;   // ip1发送的数据包数
    uint32_t ip1_send_bytes_count;     // ip1发送的字节数
    uint32_t ip2_send_packets_count;   // ip2发送的数据包数
    uint32_t ip2_send_bytes_count;     // ip2发送的字节数
    uint32_t packet_count;           // 数据包数量
    uint32_t total_bytes;            // 总字节数、

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("session_id", session_id, allocator);
        obj.AddMember("ip1", rapidjson::Value(ip1.c_str(), allocator), allocator);
        obj.AddMember("ip1_port", ip1_port, allocator);
        obj.AddMember("ip1_location", rapidjson::Value(ip1_location.c_str(), allocator), allocator);
        obj.AddMember("ip2", rapidjson::Value(ip2.c_str(), allocator), allocator);
        obj.AddMember("ip2_port", ip2_port, allocator);
        obj.AddMember("ip2_location", rapidjson::Value(ip2_location.c_str(), allocator), allocator);
        obj.AddMember("trans_proto", rapidjson::Value(trans_proto.c_str(), allocator), allocator);
        obj.AddMember("app_proto", rapidjson::Value(app_proto.c_str(), allocator), allocator);
        obj.AddMember("start_time", start_time, allocator);
        obj.AddMember("end_time", end_time, allocator);
        obj.AddMember("ip1_send_packets_count", ip1_send_packets_count, allocator);
        obj.AddMember("ip1_send_bytes_count", ip1_send_bytes_count, allocator);
        obj.AddMember("ip2_send_packets_count", ip2_send_packets_count, allocator);
        obj.AddMember("ip2_send_bytes_count", ip2_send_bytes_count, allocator);
        obj.AddMember("packet_count", packet_count, allocator);
        obj.AddMember("total_bytes", total_bytes, allocator);
    }
};
