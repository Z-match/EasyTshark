#include "TsharkManager.h"
#include <Windows.h>
#include "ProcessUtil.h"

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#else
    setlocale(LC_ALL, "zh_CN.UTF-8");
#endif // _WIN32

    loguru::init(argc, argv);
    loguru::add_file("logs.txt", loguru::Append, loguru::Verbosity_MAX);

    TsharkManager tsharkManager("D:/Code/c++/Lesson4EasyTshark/Lesson4EasyTshark/");
    //tsharkManager.analysisFile("D:/Code/c++/Lesson4EasyTshark/packets.pcap");
    //std::string analysis_file;
    //LOG_F(INFO, "请输入要分析的PCAP文件路径：");
    //std::cin >> analysis_file;
    //tsharkManager.analysisFile(analysis_file);
    //tsharkManager.printAllPackets();

    //std::vector<AdapterInfo> adaptors = tsharkManager.getNetworkAdapters();
    //for (auto item : adaptors) {
    //    LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    //}

    tsharkManager.startCapture("WLAN 3");

    // 主线程进入命令等待停止抓包
    std::string input;
    while (true) {
        std::cout << "请输入q退出抓包：";
        std::cin >> input;
        if (input == "q") {
            tsharkManager.stopCapture();
            break;
        }
    }

    // 打印所有捕获到的数据包信息
    tsharkManager.printAllPackets();

    //// 启动监控
    //tsharkManager.startMonitorAdaptersFlowTrend();

    //// 睡眠10秒，等待监控网卡数据
    //std::this_thread::sleep_for(std::chrono::seconds(60));

    //// 读取监控到的数据
    //std::map<std::string, std::map<long, long>> trendData;
    //tsharkManager.getAdaptersFlowTrendData(trendData);

    //// 停止监控
    //tsharkManager.stopMonitorAdaptersFlowTrend();

    //// 把获取到的数据打印输出
    //rapidjson::Document resDoc;
    //rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
    //resDoc.SetObject();
    //rapidjson::Value dataObject(rapidjson::kObjectType);
    //for (const auto& adaptorItem : trendData) {
    //    rapidjson::Value adaptorDataList(rapidjson::kArrayType);
    //    for (const auto& timeItem : adaptorItem.second) {
    //        rapidjson::Value timeObj(rapidjson::kObjectType);
    //        timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
    //        timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
    //        adaptorDataList.PushBack(timeObj, allocator);
    //    }

    //    dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
    //}

    //resDoc.AddMember("data", dataObject, allocator);

    //// 序列化为 JSON 字符串
    //rapidjson::StringBuffer buffer;
    //rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    //resDoc.Accept(writer);

    //LOG_F(INFO, "网卡流量监控数据: %s", buffer.GetString());

    return 0;
}

