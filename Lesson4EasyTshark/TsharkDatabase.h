#pragma once
#include "sqlite3/sqlite3.h"
#include "MiscUtil.h"
#include "loguru/loguru.hpp"
#include <mutex>
#include "QueryCondition.h"
#include "PacketSQL.h"
#include <unordered_set>
#include "Session.h"
#include "SessionSQL.h"
#include "IPStatsInfo.h"
#include "StatsSQL.h"
#include "CountryStatsInfo.h"
#include "ProtoStatsInfo.h"
#include <Windows.h>

// 数据库类
class TsharkDatabase {
public:
    // 构造函数，初始化数据库并创建表
    TsharkDatabase(const std::string& dbName) {
        // 删除之前的旧文件（如果有的话）
        remove(dbName.c_str());
        // 打开数据库连接
        if (sqlite3_open(dbName.c_str(), &db) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database");
        }

        createPacketTable();
        createSessionTable();
    }

    // 析构函数，关闭数据库连接
    ~TsharkDatabase() {
        if (db) {
            sqlite3_close(db);
        }
    }

    bool createPacketTable();
    bool storePackets(std::vector<std::shared_ptr<Packet>>& packets);
    bool queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>>& packetList, int& total);
    // 创建会话表
    void createSessionTable();
    void storeAndUpdateSessions(std::unordered_set<std::shared_ptr<Session>>& sessions);
    bool querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList, int& total);
    bool queryIPStats(QueryCondition& condition, std::vector<std::shared_ptr<IPStatsInfo>>& ipStatsList, int& total);
    bool queryCountryStats(QueryCondition& condition,
        std::vector<std::shared_ptr<CountryStatsInfo>>& countryStatsList,
        int& total);
    bool queryProtoStats(QueryCondition& condition,
        std::vector<std::shared_ptr<ProtoStatsInfo>>& protoStatsList,
        int& total);
private:
    sqlite3* db = nullptr; // SQLite 数据库连接
};

