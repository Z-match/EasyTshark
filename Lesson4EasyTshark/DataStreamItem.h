#pragma once
#include "Session.h"
class DataStreamItem : public BaseDataObject {
public:
    std::string hexData;
    std::string srcNode;
    std::string dstNode;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("hexData", rapidjson::Value(hexData.c_str(), allocator), allocator);
        obj.AddMember("srcNode", rapidjson::Value(srcNode.c_str(), allocator), allocator);
        obj.AddMember("dstNode", rapidjson::Value(dstNode.c_str(), allocator), allocator);
    }
};
