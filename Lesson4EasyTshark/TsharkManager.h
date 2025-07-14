#pragma once
//#include "rapidjson/document.h"
//#include "rapidjson/writer.h"
//#include "rapidjson/prettywriter.h"
//#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <loguru/loguru.hpp>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <set>
#include <thread>
#include <WinSock2.h>
#include <Windows.h>
#include "ProcessUtil.h"
#include <map>
#include <mutex>
#include "AdapterMonitorInfo.h"
#include <codecvt>
#include "MiscUtil.h"
#include "translator.hpp"
#include "TsharkDatabase.h"
#include <thread>
#include <chrono>
#include "Session.h"
#include "FiveTupleHash.h"
#include "DataStreamCountInfo.h"
#include "DataStreamItem.h"


#ifdef _WIN32
    // 使用宏来处理Windows和Unix的不同popen实现
#define popen _popen
#define pclose _pclose
typedef DWORD PID_T;
#else
typedef pid_t PID_T;
#endif

enum WORK_STATUS {
    STATUS_IDLE = 0,                    // 空闲状态
    STATUS_ANALYSIS_FILE = 1,           // 离线分析文件中
    STATUS_CAPTURING = 2,               // 在线采集抓包中
    STATUS_MONITORING = 3               // 监控网卡流量中
};

class TsharkManager
{
public:
    TsharkManager(std::string workDir);
    ~TsharkManager();

    // 分析数据包文件
    bool analysisFile(std::string filePath);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

    // 枚举网卡列表
    std::vector<AdapterInfo> getNetworkAdapters();

    // 开始抓包
    bool startCapture(std::string adapterName);

    // 停止抓包
    bool stopCapture();

    // 开始监控所有网卡流量统计数据
    void startMonitorAdaptersFlowTrend();

    // 获取指定网卡的流量趋势数据
    void adapterFlowTrendMonitorThreadEntry(std::string adapterName);

    // 负责存储数据包和会话信息的存储线程函数
    void storageThreadEntry();

    // 停止监控所有网卡流量统计数据
    void stopMonitorAdaptersFlowTrend();

    // 获取所有网卡流量统计数据
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

    // 获取指定数据包的详情内容
    bool getPacketDetailInfo(uint32_t frameNumber, rapidjson::Document& detailJson);

    // 转发调用数据包的接口
    void queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>>& packets, int& total);

    // 将数据包格式转换为旧的pcap格式
    bool convertToPcap(const std::string& inputFile, const std::string& outputFile);

    // 获取当前工作状态
    WORK_STATUS getWorkStatus();

    // 对TsharkManager的内部相关变量进行一个重置
    void reset();

    // 打印所有会话信息
    void printAllSessions();

    // 转发调用会话的接口
    void querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList, int& total);

    bool getIPStatsList(QueryCondition& condition, std::vector<std::shared_ptr<IPStatsInfo>>& sessionList, int& total);

    bool getProtoStatsList(QueryCondition& condition,
        std::vector<std::shared_ptr<ProtoStatsInfo>>& protoStatsList,
        int& total);

    bool getCountryStatsList(QueryCondition& condition,
        std::vector<std::shared_ptr<CountryStatsInfo>>& countryStatsList,
        int& total);

    // 获取会话数据流
    DataStreamCountInfo getSessionDataStream(uint32_t sessionId, std::vector<DataStreamItem>& dataStreamList);

    bool savePacket(std::string savePath);

private:
    // 解析每一行
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);
    //解析Epoch time
    std::string epoch_to_formatted(double epoch_time);
    // 在线采集数据包的工作线程
    void captureWorkThreadEntry(std::string adapterName);

    // 处理每一个数据包
    void processPacket(std::shared_ptr<Packet> packet);

    std::string utf8ToGbk(const std::string& utf8Str);

private:

    std::string tsharkPath;
    std::string editcapPath;
    IP2RegionUtil ip2RegionUtil;
    std::string workDir;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;

    // 在线分析线程
    std::shared_ptr<std::thread> captureWorkThread;

    // 是否停止抓包的标记
    bool stopFlag;

    // 在线抓包的tshark进程PID
    PID_T captureTsharkPid = 0;

    // 后台流量趋势监控信息
    std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;
    // 访问上面流量趋势数据的锁
    std::recursive_mutex adapterFlowTrendMapLock;

    long adapterFlowTrendMonitorStartTime = 0;

    Traslator translator;

    // 等待存储入库的数据
    std::vector<std::shared_ptr<Packet>> packetsTobeStore;

    // 访问待存储数据的锁
    std::mutex storeLock;

    // 存储线程，负责将获取到的数据包和会话信息存储入库
    std::shared_ptr<std::thread> storageThread;

    // 数据库存储
    std::shared_ptr<TsharkDatabase> storage;

    // 工作状态
    WORK_STATUS workStatus = STATUS_IDLE;
    std::recursive_mutex workStatusLock;

    // 会话表
    std::unordered_map<FiveTuple, std::shared_ptr<Session>, FiveTupleHash> sessionMap;

    std::map<uint8_t, std::string> ipProtoMap = {
        {1, "ICMP"},
        {2, "IGMP"},
        {6, "TCP"},
        {17, "UDP"},
        {47, "GRE"},
        {50, "ESP"},
        {51, "AH"},
        {88, "EIGRP"},
        {89, "OSPF"},
        {132, "SCTP"}
    };

    // 等待存储入库的会话列表
    std::unordered_set<std::shared_ptr<Session>> sessionSetTobeStore;

    std::map<uint32_t, std::shared_ptr<Session>> sessionIdMap;
};
