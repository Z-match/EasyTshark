#pragma once

#include <string>
#include <sstream>
#include <iostream>
#include "../tshark_datatype.h"
#include "loguru/loguru.hpp"
#include "QueryCondition.h"
#include "PageHelper.h"

class PacketSQL {
public:
    static std::string buildPacketQuerySQL(QueryCondition& condition) {

        std::string sql;
        std::stringstream ss;
        ss << "SELECT * FROM t_packets";

        std::vector<std::string> conditionList;

        if (!condition.mac.empty()) {
            std::string mac = replaceWildcards(condition.mac);
            conditionList.push_back("(src_mac LIKE '" + mac + "' OR dst_mac LIKE '" + mac + "')");
        }
        if (!condition.ip.empty()) {
            std::string ip = replaceWildcards(condition.ip);
            conditionList.push_back("(src_ip LIKE '" + ip + "' OR dst_ip LIKE '" + ip + "')");
        }
        // 端口查询（精确匹配）
        if (condition.port != 0) {
            conditionList.push_back("(src_port = " + std::to_string(condition.port) +
                " OR dst_port = " + std::to_string(condition.port) + ")");
        }

        // 归属地查询（模糊匹配）
        if (!condition.location.empty()) {
            std::string location = replaceWildcards(condition.location);
            conditionList.push_back("(src_location LIKE '" + location + "' OR dst_location LIKE '" + location + "')");
        }

        // 协议查询
        if (!condition.proto.empty()) {
            conditionList.push_back("protocol = '" + condition.proto + "'");
        }

        if (condition.session_id != 0) {
            char buf[100] = { 0 };
            snprintf(buf, sizeof(buf), "belong_session_id=%d", condition.session_id);
            conditionList.push_back(buf);
        }

        // 组合条件
        if (!conditionList.empty()) {
            ss << " WHERE ";
            for (size_t i = 0; i < conditionList.size(); ++i) {
                if (i > 0) ss << " AND ";
                ss << conditionList[i];
            }
        }

        ss << PageHelper::getPageSql();

        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    static std::string buildPacketQuerySQL_Count(QueryCondition& condition) {
        std::string sql = buildPacketQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }

private:
    static std::string replaceWildcards(const std::string& input) {
        std::string result = input;
        // 替换 * 为SQL的 %
        size_t pos = 0;
        while ((pos = result.find('*', pos)) != std::string::npos) {
            result.replace(pos, 1, "%");
            pos += 1;
        }
        return result;
    }
};

