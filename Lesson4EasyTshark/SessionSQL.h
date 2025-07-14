#pragma once
#include <iostream>
#include "QueryCondition.h"
#include <vector>
#include "loguru/loguru.hpp"
#include <sstream>
#include "PageHelper.h"

class SessionSQL {
public:
    static std::string buildSessionQuerySQL(QueryCondition& condition) {

        std::string sql;
        std::stringstream ss;
        ss << "SELECT * FROM t_sessions";

        std::vector<std::string> conditionList;
        if (!condition.proto.empty()) {
            char buf[100] = { 0 };
            snprintf(buf, sizeof(buf), "(app_proto like '%%%s%%' or trans_proto like '%%%s%%')", condition.proto.c_str(), condition.proto.c_str());
            conditionList.push_back(buf);
        }
        if (!condition.ip.empty()) {
            std::string ip = replaceWildcards(condition.ip);
            conditionList.push_back("(src_ip LIKE '" + ip + "' OR dst_ip LIKE '" + ip + "')");
        }
        if (condition.port != 0) {
            char buf[100] = { 0 };
            snprintf(buf, sizeof(buf), "(ip1_port=%d or ip2_port=%d)", condition.port, condition.port);
            conditionList.push_back(buf);
        }
        if (condition.session_id != 0) {
            char buf[100] = { 0 };
            snprintf(buf, sizeof(buf), "(session_id=%d)", condition.session_id);
            conditionList.push_back(buf);
        }

        // 拼接 WHERE 条件
        if (!conditionList.empty()) {
            ss << " WHERE ";
            for (size_t i = 0; i < conditionList.size(); ++i) {
                if (i > 0) {
                    ss << " AND ";
                }
                ss << conditionList[i];
            }
        }

        ss << PageHelper::getPageSql();

        sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    static std::string buildSessionQuerySQL_Count(QueryCondition& condition) {
        std::string sql = buildSessionQuerySQL(condition);
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

