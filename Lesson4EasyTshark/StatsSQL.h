#pragma once

#include <string>
#include <sstream>
#include <iostream>
#include "loguru/loguru.hpp"
#include "QueryCondition.h"
#include "PageHelper.h"

class StatsSQL {
public:
    // 构建IP统计查询SQL
    // 构建IP统计查询SQL (适配t_sessions表结构)
    static std::string buildIPStatsQuerySQL(QueryCondition& condition) {
        std::stringstream sql;

        sql << "SELECT ip, location, MIN(start_time) AS earliest_time, MAX(end_time) AS latest_time, "
            << "GROUP_CONCAT(DISTINCT port) AS ports, "
            << "GROUP_CONCAT(DISTINCT trans_proto) AS trans_protos, "
            << "GROUP_CONCAT(DISTINCT app_proto) AS app_protos, "
            << "SUM(sent_packets) AS total_sent_packets, "
            << "SUM(sent_bytes) AS total_sent_bytes, "
            << "SUM(recv_packets) AS total_recv_packets, "
            << "SUM(recv_bytes) AS total_recv_bytes, "
            << "SUM(tcp_sessions) AS tcp_session_count, "
            << "SUM(udp_sessions) AS udp_session_count "
            << "FROM ("
            << "  SELECT "
            << "    ip1 AS ip, "
            << "    ip1_location AS location, "
            << "    start_time, "
            << "    end_time, "
            << "    ip1_port AS port, "
            << "    trans_proto, "
            << "    app_proto, "
            << "    ip1_send_packets_count AS sent_packets, "
            << "    ip1_send_bytes_count AS sent_bytes, "
            << "    ip2_send_packets_count AS recv_packets, "
            << "    ip2_send_bytes_count AS recv_bytes, "
            << "    CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions, "
            << "    CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions "
            << "  FROM t_sessions ";
        appendSessionWhereClause(sql, condition, true);

        sql << "  UNION ALL "
            << "  SELECT "
            << "    ip2 AS ip, "
            << "    ip2_location AS location, "
            << "    start_time, "
            << "    end_time, "
            << "    ip2_port AS port, "
            << "    trans_proto, "
            << "    app_proto, "
            << "    ip2_send_packets_count AS sent_packets, "
            << "    ip2_send_bytes_count AS sent_bytes, "
            << "    ip1_send_packets_count AS recv_packets, "
            << "    ip1_send_bytes_count AS recv_bytes, "
            << "    CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions, "
            << "    CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions "
            << "  FROM t_sessions ";
        appendSessionWhereClause(sql, condition, false);

        sql << ") t "
            << "GROUP BY ip "
            << "ORDER BY " << condition.sortField << " " << condition.sortOrder << " "
            << "LIMIT " << condition.pageSize << " OFFSET " << ((condition.pageNum - 1) * condition.pageSize);

        return sql.str();
    }

    // 构建IP统计总数查询SQL
    static std::string buildIPStatsQuerySQL_Count(QueryCondition& condition) {
        std::stringstream sql;

        sql << "SELECT COUNT(DISTINCT ip) FROM ("
            << "  SELECT ip1 AS ip FROM t_sessions ";
        appendSessionWhereClause(sql, condition, true);

        sql << "  UNION ALL "
            << "  SELECT ip2 AS ip FROM t_sessions ";
        appendSessionWhereClause(sql, condition, false);

        sql << ") t";

        return sql.str();
    }

    // 构建协议统计查询SQL
    static std::string buildProtoStatsQuerySQL(QueryCondition& condition) {
        std::stringstream sql;

        sql << "SELECT "
            << "protocol, "
            << "SUM(packet_count) AS total_packets, "
            << "SUM(total_bytes) AS total_bytes, "
            << "COUNT(DISTINCT session_id) AS session_count "
            << "FROM ("
            << "  SELECT session_id, trans_proto AS protocol, packet_count, total_bytes "
            << "  FROM t_sessions "
            << "  WHERE trans_proto IS NOT NULL AND trans_proto != '' ";
        appendSessionWhereClause(sql, condition, false, false); // 不添加WHERE前缀

        sql << "  UNION ALL "
            << "  SELECT session_id, app_proto AS protocol, packet_count, total_bytes "
            << "  FROM t_sessions "
            << "  WHERE app_proto IS NOT NULL AND app_proto != '' ";
        appendSessionWhereClause(sql, condition, false, false); // 不添加WHERE前缀

        sql << ") AS combined "
            << "GROUP BY protocol "
            << "ORDER BY " << condition.sortField << " " << condition.sortOrder << " "
            << "LIMIT " << condition.pageSize << " OFFSET " << ((condition.pageNum - 1) * condition.pageSize);

        return sql.str();
    }

    // 构建协议统计总数查询SQL
    static std::string buildProtoStatsQuerySQL_Count(QueryCondition& condition) {
        std::stringstream sql;

        sql << "SELECT COUNT(DISTINCT protocol) FROM ("
            << "  SELECT trans_proto AS protocol FROM t_sessions "
            << "  WHERE trans_proto IS NOT NULL AND trans_proto != '' ";
        appendSessionWhereClause(sql, condition, false, false);

        sql << "  UNION ALL "
            << "  SELECT app_proto AS protocol FROM t_sessions "
            << "  WHERE app_proto IS NOT NULL AND app_proto != '' ";
        appendSessionWhereClause(sql, condition, false, false);

        sql << ") t";

        return sql.str();
    }
    // 构建国家统计查询SQL
    static std::string buildCountryStatsQuerySQL(QueryCondition& condition) {
        std::stringstream sql;

        sql << "SELECT country, "
            << "SUM(sent_packets) AS sent_packets, "
            << "SUM(sent_bytes) AS sent_bytes, "
            << "SUM(recv_packets) AS recv_packets, "
            << "SUM(recv_bytes) AS recv_bytes, "
            << "COUNT(DISTINCT ip) AS ip_count "
            << "FROM ("
            << "  SELECT "
            << "    CASE "
            << "      WHEN ip1_location LIKE '%-%' THEN SUBSTR(ip1_location, 1, INSTR(ip1_location, '-')-1) "
            << "      WHEN ip1_location = '内网' THEN '内网' "
            << "      ELSE ip1_location "
            << "    END AS country, "
            << "    ip1 AS ip, "
            << "    ip1_send_packets_count AS sent_packets, "
            << "    ip1_send_bytes_count AS sent_bytes, "
            << "    ip2_send_packets_count AS recv_packets, "
            << "    ip2_send_bytes_count AS recv_bytes "
            << "  FROM t_sessions ";
        appendSessionWhereClause(sql, condition, true);

        sql << "  UNION ALL "
            << "  SELECT "
            << "    CASE "
            << "      WHEN ip2_location LIKE '%-%' THEN SUBSTR(ip2_location, 1, INSTR(ip2_location, '-')-1) "
            << "      WHEN ip2_location = '内网' THEN '内网' "
            << "      ELSE ip2_location "
            << "    END AS country, "
            << "    ip2 AS ip, "
            << "    ip2_send_packets_count AS sent_packets, "
            << "    ip2_send_bytes_count AS sent_bytes, "
            << "    ip1_send_packets_count AS recv_packets, "
            << "    ip1_send_bytes_count AS recv_bytes "
            << "  FROM t_sessions ";
        appendSessionWhereClause(sql, condition, false);

        sql << ") t "
            << "WHERE country <> '' "  // 保留过滤空值
            << "GROUP BY country "
            << "ORDER BY " << condition.sortField << " " << condition.sortOrder << " "
            << "LIMIT " << condition.pageSize << " OFFSET " << ((condition.pageNum - 1) * condition.pageSize);

        return sql.str();
    }
    // 构建国家统计总数查询SQL
    static std::string buildCountryStatsQuerySQL_Count(QueryCondition& condition) {
        std::stringstream sql;

        sql << "SELECT COUNT(DISTINCT country) FROM ("
            << "  SELECT "
            << "    CASE "
            << "      WHEN ip1_location LIKE '%-%' THEN SUBSTR(ip1_location, 1, INSTR(ip1_location, '-')-1) "
            << "      WHEN ip1_location = '内网' THEN '内网' "
            << "      ELSE ip1_location "
            << "    END AS country "
            << "  FROM t_sessions ";
        appendSessionWhereClause(sql, condition, true);

        sql << "  UNION ALL "
            << "  SELECT "
            << "    CASE "
            << "      WHEN ip2_location LIKE '%-%' THEN SUBSTR(ip2_location, 1, INSTR(ip2_location, '-')-1) "
            << "      WHEN ip2_location = '内网' THEN '内网' "
            << "      ELSE ip2_location "
            << "    END AS country "
            << "  FROM t_sessions ";
        appendSessionWhereClause(sql, condition, false);

        sql << ") t WHERE country <> ''";

        return sql.str();
    }private:
    // 添加WHERE子句
    static void appendSessionWhereClause(std::stringstream& sql, QueryCondition& condition,
        bool is_first_ip, bool add_where_prefix = true) {
        std::string ipField = is_first_ip ? "ip1" : "ip2";
        std::string locField = is_first_ip ? "ip1_location" : "ip2_location";
        bool hasCondition = false;

        // IP条件
        if (!condition.ip.empty()) {
            sql << (add_where_prefix ? " WHERE " : (hasCondition ? " AND " : " WHERE "))
                << ipField << " LIKE '%" << condition.ip << "%'";
            hasCondition = true;
        }

        // 地理位置条件
        if (!condition.location.empty()) {
            sql << (hasCondition ? " AND " : (add_where_prefix ? " WHERE " : " AND "))
                << locField << " LIKE '%" << condition.location << "%'";
            hasCondition = true;
        }

        // 时间范围条件
        if (condition.startTime > 0) {
            sql << (hasCondition ? " AND " : (add_where_prefix ? " WHERE " : " AND "))
                << "start_time >= " << condition.startTime;
            hasCondition = true;
        }

        if (condition.endTime > 0) {
            sql << (hasCondition ? " AND " : (add_where_prefix ? " WHERE " : " AND "))
                << "end_time <= " << condition.endTime;
            hasCondition = true;
        }

        // 协议条件
        if (!condition.protocols.empty()) {
            std::string protoCondition;
            for (const auto& proto : condition.protocols) {
                if (!protoCondition.empty()) protoCondition += " OR ";
                protoCondition += "(trans_proto = '" + proto + "' OR app_proto = '" + proto + "')";
            }
            sql << (hasCondition ? " AND " : (add_where_prefix ? " WHERE " : " AND "))
                << "(" << protoCondition << ")";
        }
    }
};

