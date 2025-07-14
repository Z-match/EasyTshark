#pragma once
#include "TsharkError.h"
#include "TsharkManager.h"
#include "httplib/httplib.h"



// 基类Controller
class BaseController {
public:
    BaseController(httplib::Server& server, std::shared_ptr<TsharkManager> tsharkManager)
        :__server(server)
        , __tsharkManager(tsharkManager) {
    }
    virtual void registerRoute() = 0;

protected:
    httplib::Server& __server;
    std::shared_ptr<TsharkManager> __tsharkManager;

public:
    // 从URL中提取整数参数
    static int getIntParam(const httplib::Request& req, std::string paramName, int defaultValue = 0) {

        int value = defaultValue;
        auto it = req.params.find(paramName);
        if (it != req.params.end()) {
            value = std::stoi(it->second);
        }
        return value;
    }

    // 从URL中提取字符串参数
    static std::string getStringParam(const httplib::Request& req, std::string paramName, std::string defaultValue = "") {
        std::string value = defaultValue;
        auto it = req.params.find(paramName);
        if (it != req.params.end()) {
            value = it->second;
        }
        return value;
    }

protected:

    // 使用模板的形式返回数据列表
    template<typename Data>
    void sendDataList(httplib::Response& res, std::vector<std::shared_ptr<Data>>& dataList, int total) {
        /**
         * 返回数据格式：
         * {
         *     "code": 0,
         *     "msg": "操作成功",
         *     "data" [] / {}
         * }
         */
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();

        // 添加 "code" 和 "msg"
        resDoc.AddMember("code", static_cast<int>(ERROR_SUCCESS), allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);
        resDoc.AddMember("total", total, allocator);

        // 构建 "data" 数组
        rapidjson::Value dataArray(rapidjson::kArrayType);
        for (const auto& data : dataList) {
            rapidjson::Value obj(rapidjson::kObjectType);
            data->toJsonObj(obj, allocator);
            assert(obj.IsObject());
            dataArray.PushBack(obj, allocator);
        }

        resDoc.AddMember("data", dataArray, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        // 设置响应内容
        res.set_content(buffer.GetString(), "application/json");
    }


    // 返回成功响应，但没有数据
    void sendSuccessResponse(httplib::Response& res) {
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", 0, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }


    // 发生错误响应
    void sendErrorResponse(httplib::Response& res, int errorCode) {
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", errorCode, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(errorCode).c_str(), allocator), allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }

    // 提取请求中的参数
    bool parseQueryCondition(const httplib::Request& req, QueryCondition& queryCondition) {

        try {

            // 首先处理URL查询参数
            queryCondition.pageNum = getIntParam(req, "pageNum", 1);
            queryCondition.pageSize = getIntParam(req, "pageSize", 100);
            queryCondition.sortField = getStringParam(req, "sortField", "total_sent_bytes");
            queryCondition.sortOrder = getStringParam(req, "sortOrder", "DESC");

            // 检查是否有body数据
            if (req.body.empty()) {
                return true; // 没有body数据也可以接受，使用默认值
            }

            // 使用RapidJSON解析JSON
            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError()) {
                LOG_F(ERROR, "JSON解析错误");
                return false;
            }

            if (!doc.IsObject()) {
                LOG_F(ERROR, "无效的JSON格式");
                return false;
            }

            // 提取所有可能字段
            if (doc.HasMember("mac") && doc["mac"].IsString()) {
                queryCondition.mac = doc["mac"].GetString();
            }
            if (doc.HasMember("ip") && doc["ip"].IsString()) {
                queryCondition.ip = doc["ip"].GetString();
            }
            if (doc.HasMember("port") && doc["port"].IsUint()) {
                queryCondition.port = static_cast<uint16_t>(doc["port"].GetUint());
            }
            if (doc.HasMember("location") && doc["location"].IsString()) {
                queryCondition.location = doc["location"].GetString();
            }
            if (doc.HasMember("proto") && doc["proto"].IsString()) {
                queryCondition.proto = doc["proto"].GetString();
            }
            if (doc.HasMember("session_id") && doc["session_id"].IsUint()) {
                queryCondition.session_id = doc["session_id"].GetUint();
            }
            if (doc.HasMember("startTime") && doc["startTime"].IsDouble()) {
                queryCondition.startTime = doc["startTime"].GetDouble();
            }
            if (doc.HasMember("endTime") && doc["endTime"].IsDouble()) {
                queryCondition.endTime = doc["endTime"].GetDouble();
            }
            if (doc.HasMember("sortField") && doc["sortField"].IsString()) {
                queryCondition.sortField = doc["sortField"].GetString();
            }
            if (doc.HasMember("sortOrder") && doc["sortOrder"].IsString()) {
                queryCondition.sortOrder = doc["sortOrder"].GetString();
            }

            // 处理protocols数组
            if (doc.HasMember("protocols") && doc["protocols"].IsArray()) {
                queryCondition.protocols.clear();
                const rapidjson::Value& protocols = doc["protocols"];
                for (rapidjson::SizeType i = 0; i < protocols.Size(); i++) {
                    if (protocols[i].IsString()) {
                        queryCondition.protocols.push_back(protocols[i].GetString());
                    }
                }
            }
            
        }
        catch (std::exception&) {
            std::cout << "parse parameter error" << std::endl;
            return false;
        }
        return true;
    }

    // 成功响应，返回JSON内容
    void sendJsonResponse(httplib::Response& res, rapidjson::Document& dataDoc) {
        /**
         * 返回数据格式：
         * {
         *     "code": 0,
         *     "msg": "操作成功",
         *     "data" [] / {}
         * }
         */
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", static_cast<int>(ERROR_SUCCESS), allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);
        resDoc.AddMember("data", dataDoc, allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }
};

