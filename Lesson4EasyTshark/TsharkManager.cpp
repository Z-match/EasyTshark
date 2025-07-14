#include "TsharkManager.h"
TsharkManager::TsharkManager(std::string workDir) {
    this->workDir = workDir;
    this->tsharkPath = workDir + "/tshark/bin/tshark.exe";
    this->editcapPath = workDir + "/tshark/bin/editcap.exe";
    std::string xdbPath = workDir + "/ip2region.xdb";
    storage = std::make_shared<TsharkDatabase>(this->workDir + "/mytshark.db");
    IP2RegionUtil::init(xdbPath);
}

TsharkManager::~TsharkManager() {
    //ip2RegionUtil.uninit();
}

bool TsharkManager::analysisFile(std::string filePath) {

    std::unique_lock<std::recursive_mutex> lock(workStatusLock);
    reset();

    // 统一转换为标准的pcap格式
    currentFilePath = MiscUtil::getPcapNameByCurrentTimestamp();
    if (!convertToPcap(filePath, currentFilePath)) {
        LOG_F(ERROR, "convert to pcap failed");
        return false;
    }

    workStatus = STATUS_ANALYSIS_FILE;

    std::vector<std::string> tsharkArgs = {
            tsharkPath,
            "-r", currentFilePath.c_str(),
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "frame.cap_len",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "ip.proto",
            "-e", "ipv6.nxt",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
    };

    std::string command;
    for (auto arg : tsharkArgs) {
        command += arg;
        command += " ";
    }

    FILE* pipe = ProcessUtil::PopenEx(command.c_str());
    if (!pipe) {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return false;
    }

    // 先启动存储线程
    stopFlag = false;
    storageThread = std::make_shared<std::thread>(&TsharkManager::storageThreadEntry, this);

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet)) {
            LOG_F(ERROR, buffer);
            assert(false); // 增加错误断言，及时发现错误
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        processPacket(packet);
    }

    pclose(pipe);

    // 等待存储线程退出
    stopFlag = true;
    workStatus = STATUS_IDLE;
    storageThread->join();
    storageThread.reset();

    //// 记录当前分析的文件路径
    //currentFilePath = filePath;

    LOG_F(INFO, "分析完成，数据包总数：%zu", allPackets.size());

    return true;
}

bool TsharkManager::parseLine(std::string line, std::shared_ptr<Packet> packet) {
    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;
 
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串

    // 字段顺序：
    // 0: frame.number
    // 1: frame.time_epoch
    // 2: frame.len
    // 3: frame.cap_len
    // 4: eth.src
    // 5: eth.dst
    // 6: ip.src
    // 7: ipv6.src
    // 8: ip.dst
    // 9: ipv6.dst
    // 10: ip.proto
    // 11: ipv6.nxt
    // 12: tcp.srcport
    // 13: udp.srcport
    // 14: tcp.dstport
    // 15: udp.dstport
    // 16: _ws.col.Protocol
    // 17: _ws.col.Info

    if (fields.size() >= 18) {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = std::stod(fields[1]);
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];

        if (!fields[10].empty() || !fields[11].empty()) {
            uint8_t transProtoNumber = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
            if (ipProtoMap.find(transProtoNumber) != ipProtoMap.end()) {
                packet->trans_proto = ipProtoMap[transProtoNumber];
            }
        }

        if (!fields[12].empty() || !fields[13].empty()) {
            packet->src_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }

        if (!fields[14].empty() || !fields[15].empty()) {
            packet->dst_port = std::stoi(fields[14].empty() ? fields[15] : fields[14]);
        }
        packet->protocol = fields[16];
        packet->info = fields[17];

        return true;
    }
    else {
        return false;
    }
}

std::string TsharkManager::epoch_to_formatted(double epoch_time) {
    //            С    
    time_t seconds = static_cast<time_t>(epoch_time);
    double fractional = epoch_time - seconds;
    int microseconds = static_cast<int>(round(fractional * 1'000'000));

    // ת  Ϊ    ʱ  
    struct tm tm;
    localtime_s(&tm, &seconds);

    //   ʽ     
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << "." << std::setfill('0') << std::setw(6) << microseconds;

    return oss.str();
}

void TsharkManager::printAllPackets() {

    for (auto pair : allPackets) {

        std::shared_ptr<Packet> packet = pair.second;

        //     JSON    
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator); 
        pktObj.AddMember("timestamp", rapidjson::Value(epoch_to_formatted(packet->time).c_str(), allocator), allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pktObj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("cap_len", packet->cap_len, allocator);
        pktObj.AddMember("len", packet->len, allocator);

        //    л Ϊ JSON  ַ   
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);

        //   ӡJSON   
        //std::cout << buffer.GetString() << std::endl;
        LOG_F(INFO, buffer.GetString());

        //   ȡ      ĵ ԭʼʮ          
        std::vector<unsigned char> data;
        getPacketHexData(packet->frame_number, data);
        // ƴ  ʮ       ַ   
        std::ostringstream hex_stream;
        hex_stream << "Packet Hex: ";
        for (unsigned char byte : data) {
            hex_stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        //   loguru   
        LOG_F(INFO, "%s", hex_stream.str().c_str());
    }

    LOG_F(INFO, "analysis completed, the total number of packets is: [%d]", allPackets.size());

    //uint32_t number;
    //LOG_F(INFO, "请输入要获取详情的数据包编号（1-%d）", allPackets.size());
    //std::cin >> number;
    //std::string res;
    //if (!getPacketDetailInfo(number, res)) {
    //    LOG_F(ERROR, "获取详情失败");
    //    return;
    //}
    ////std::cout << res << std::endl;
    //// 写入文件
    //std::string jsonName = std::to_string(number) + "-" + std::to_string(allPackets.size()) + ".json";
    //std::ofstream out(jsonName);
    //out << res;
    //out.close();
}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data) {
    // 获取指定编号数据包的信息
    if (allPackets.find(frameNumber) == allPackets.end()) {
        std::cerr << "找不到编号为 " << frameNumber << " 的数据包" << std::endl;
        return false;
    }
    std::shared_ptr<Packet> packet = allPackets[frameNumber];
    
    std::ifstream file(currentFilePath, std::ios::binary);
    if (!file) {
        LOG_F(ERROR, "can't open the file!");
        return false;
    }

    // 移动到指定偏移位置
    file.seekg(allPackets[frameNumber]->file_offset, std::ios::beg);

    // 读取数据
    uint32_t length = allPackets[frameNumber]->cap_len;
    data.resize(length);
    file.read(reinterpret_cast<char*>(data.data()), length);

    file.close();
    return true;

}

std::vector<AdapterInfo> TsharkManager::getNetworkAdapters() {
    // 需要过滤的虚拟网卡
    std::set<std::string> specialInterfaces = { "sshdump", "ciscodump", "udpdump", "randpkt", "wifidump.exe", "etwdump", "sshdump.exe", "\\\\.\\USBPcap1", "\\\\.\\USBPcap2"};
    std::vector<AdapterInfo> interfaces;
    char buffer[256] = { 0 };
    std::string result;

    // 启动tshark -D命令
    std::string cmd = tsharkPath + " -D";
    FILE* pipe = ProcessUtil::PopenEx(cmd.c_str());
    if (!pipe) {
        throw std::runtime_error("Failed to run tshark command.");
    }

    // 读取tshark输出
    while (fgets(buffer, 256, pipe) != nullptr) {
        result += buffer;
    }

    // 解析tshark的输出，输出格式为：
    // 1. \Device\NPF_{xxxxxx} (网卡描述)
    std::istringstream stream(result);
    std::string line;
    int index = 1;
    while (std::getline(stream, line)) {
        // ͨ   ո    ֶ 
        int startPos = line.find(' ');
        if (startPos != std::string::npos) {
            int endPos = line.find(' ', startPos + 1);
            std::string interfaceName;
            if (endPos != std::string::npos) {
                interfaceName = line.substr(startPos + 1, endPos - startPos - 1);
            }
            else {
                interfaceName = line.substr(startPos + 1);
            }

            // 过滤特殊网卡
            if (specialInterfaces.find(interfaceName) != specialInterfaces.end()) {
                continue;
            }

            AdapterInfo adapterInfo;
            adapterInfo.name = interfaceName;
            adapterInfo.id = index++;

            if (line.find("(") != std::string::npos && line.find(")") != std::string::npos) {
                adapterInfo.remark = line.substr(line.find("(") + 1, line.find(")") - line.find("(") - 1);
            }

#ifdef _WIN32
            // 在Windows平台上，name是设备名，如果有备注名称，就使用备注名称
            if (!adapterInfo.remark.empty()) {
                adapterInfo.name = adapterInfo.remark;
            }
#endif // _WIN32
            interfaces.push_back(adapterInfo);
        }
    }

    pclose(pipe);

    return interfaces;
}

// 开始抓包
bool TsharkManager::startCapture(std::string adapterName) {

    std::unique_lock<std::recursive_mutex> lock(workStatusLock);
    reset();
    LOG_F(INFO, "即将开始抓包，网卡：%s", adapterName.c_str());
    stopFlag = false;
    workStatus = STATUS_CAPTURING;
    storageThread = std::make_shared<std::thread>(&TsharkManager::storageThreadEntry, this);
    captureWorkThread = std::make_shared<std::thread>(&TsharkManager::captureWorkThreadEntry, this, "\"" + adapterName + "\"");
    return true;
}

std::string TsharkManager::utf8ToGbk(const std::string& utf8Str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8conv;
    std::wstring wstr = utf8conv.from_bytes(utf8Str);

    std::vector<char> buf(wstr.size() * 2 + 1);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, buf.data(), buf.size(), nullptr, nullptr);

    return std::string(buf.data());
}

void TsharkManager::captureWorkThreadEntry(std::string adapterName) {

    currentFilePath = MiscUtil::getPcapNameByCurrentTimestamp();
    std::vector<std::string> tsharkArgs = {
            tsharkPath,
            "-i", adapterName.c_str(),
            "-w", currentFilePath,           // 默认将采集到的数据包写入到这个文件下
            "-F", "pcap",                    // 指定存储的格式为PCAP格式
            "-l",                            // 指定tshark使用行缓冲模式，及时打印输出抓包的包信息
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "frame.cap_len",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "ip.proto",
            "-e", "ipv6.nxt",
            "-e", "tcp.srcport",
            "-e", "udp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info",
    };

    std::string command;
    for (auto arg : tsharkArgs) {
        command += arg;
        command += " ";
    }

    FILE* pipe = ProcessUtil::PopenEx(command.c_str(), &captureTsharkPid);
    if (!pipe) {
        LOG_F(ERROR, "Failed to run tshark command!");
        return;
    }

    char buffer[4096];

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr && !stopFlag) {
        std::string line = buffer;
        if (line.find("Capturing on") != std::string::npos) {
            continue;
        }

        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(line, packet)) {
            LOG_F(ERROR, buffer);
            assert(false);
        }

        // 计算当前报文的偏移，然后记录在Packet对象中
        packet->file_offset = file_offset + sizeof(PacketHeader);

        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取IP地理位置
        packet->src_location = IP2RegionUtil::getIpLocation(packet->src_ip);
        packet->dst_location = IP2RegionUtil::getIpLocation(packet->dst_ip);

        processPacket(packet);
    }

    pclose(pipe);
}
// 停止抓包
bool TsharkManager::stopCapture() {

    std::unique_lock<std::recursive_mutex> lock(workStatusLock);
    LOG_F(INFO, "即将停止抓包");
    stopFlag = true;
    ProcessUtil::Kill(captureTsharkPid);

    // 等待抓包处理线程退出
    captureWorkThread->join();
    captureWorkThread.reset();

    // 等待存储线程退出
    storageThread->join();
    storageThread.reset();

    // 最后把状态重置
    workStatus = STATUS_IDLE;

    return true;
}

// 开始监控所有网卡流量统计数据
void TsharkManager::startMonitorAdaptersFlowTrend() {

    reset();
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    adapterFlowTrendMapLock.lock();
    adapterFlowTrendMonitorMap.clear();
    adapterFlowTrendMapLock.unlock();
    adapterFlowTrendMonitorStartTime = time(nullptr);

    // 第一步：获取网卡列表
    std::vector<AdapterInfo> adapterList = getNetworkAdapters();

    // 第二步：每个网卡启动一个线程，统计对应网卡的数据
    for (auto adapter : adapterList) {
        adapterFlowTrendMonitorMap.insert(std::make_pair<>(adapter.name, AdapterMonitorInfo()));
        AdapterMonitorInfo& monitorInfo = adapterFlowTrendMonitorMap.at(adapter.name);

        monitorInfo.monitorThread = std::make_shared<std::thread>(&TsharkManager::adapterFlowTrendMonitorThreadEntry, this, adapter.name);
        if (monitorInfo.monitorThread == nullptr) {
            LOG_F(ERROR, "监控线程创建失败，网卡名：%s", adapter.name.c_str());
        }
        else {
            LOG_F(INFO, "监控线程创建成功，网卡名：%s，monitorThread: %p", adapter.name.c_str(), monitorInfo.monitorThread.get());
        }
    }

    workStatus = STATUS_MONITORING;
}

// 获取指定网卡的流量趋势数据
void TsharkManager::adapterFlowTrendMonitorThreadEntry(std::string adapterName) {
    adapterFlowTrendMapLock.lock();
    if (adapterFlowTrendMonitorMap.find(adapterName) == adapterFlowTrendMonitorMap.end()) {
        adapterFlowTrendMapLock.unlock();
        return;
    }
    adapterFlowTrendMapLock.unlock();

    char buffer[256] = { 0 };
    std::map<long, long>& trafficPerSecond = adapterFlowTrendMonitorMap[adapterName].flowTrendData;

    // Tshark命令，指定网卡，实时捕获时间戳和数据包长度
    std::string tsharkCmd = tsharkPath + " -i \"" + adapterName + "\" -T fields -e frame.time_epoch -e frame.len";
    std::string gbkCommand = utf8ToGbk(tsharkCmd.c_str());

    LOG_F(INFO, "启动网卡流量监控: %s", gbkCommand.c_str());

    PID_T tsharkPid = 0;
    FILE* pipe = ProcessUtil::PopenEx(gbkCommand.c_str(), &tsharkPid);
    if (!pipe) {
        throw std::runtime_error("Failed to run tshark command.");
    }

    // 将管道保存起来
    adapterFlowTrendMapLock.lock();
    adapterFlowTrendMonitorMap[adapterName].monitorTsharkPipe = pipe;
    adapterFlowTrendMonitorMap[adapterName].tsharkPid = tsharkPid;
    adapterFlowTrendMapLock.unlock();

    // 逐行读取tshark输出
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line(buffer);
        std::istringstream iss(line);
        std::string timestampStr, lengthStr;

        if (line.find("Capturing") != std::string::npos || line.find("captured") != std::string::npos) {
            continue;
        }

        // 解析每行的时间戳和数据包长度
        if (!(iss >> timestampStr >> lengthStr)) {
            continue;
        }

        try {
            // 转换时间戳为long类型，秒数部分
            long timestamp = static_cast<long>(std::stod(timestampStr));

            // 转换数据包长度为long类型
            long packetLength = std::stol(lengthStr);

            // 每秒的字节数累加
            trafficPerSecond[timestamp] += packetLength;

            // 如果trafficPerSecond超过300秒，则删除最早的数据，始终只存储最近300秒的数据
            while (trafficPerSecond.size() > 300) {
                // 访问并删除最早的时间戳数据
                auto it = trafficPerSecond.begin();
                LOG_F(INFO, "Removing old data for second: %ld, Traffic: %ld bytes", it->first, it->second);
                trafficPerSecond.erase(it);
            }

        }
        catch (const std::exception& e) {
            // 处理转换错误
            LOG_F(ERROR, "Error parsing tshark output: %s", line.c_str());
        }
    }

    LOG_F(INFO, "adapterFlowTrendMonitorThreadEntry 已结束");
}

// 停止监控所有网卡流量统计数据
void TsharkManager::stopMonitorAdaptersFlowTrend() {

    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    // 先杀死对应的tshark进程
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {
        ProcessUtil::Kill(adapterPipePair.second.tsharkPid);
    }

    // 然后关闭管道
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {

        // 然后关闭管道
        pclose(adapterPipePair.second.monitorTsharkPipe);

        if (adapterPipePair.second.monitorThread == nullptr) {
            LOG_F(ERROR, "发现监控线程nullptr，网卡名：%s", adapterPipePair.first.c_str());
            continue;
        }

        // 最后等待对应线程退出
        adapterPipePair.second.monitorThread->join();

        LOG_F(INFO, "网卡：%s 流量监控已停止", adapterPipePair.first.c_str());
    }

    workStatus = STATUS_IDLE;

    adapterFlowTrendMonitorMap.clear();
}
// 获取所有网卡流量统计数据
void TsharkManager::getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData) {

    long timeNow = time(nullptr);

    // 数据从最左边冒出来
    // 一开始：以最开始监控时间为左起点，终点为未来300秒
    // 随着时间推移，数据逐渐填充完这300秒
    // 超过300秒之后，结束节点就是当前，开始节点就是当前-300
    long startWindow = timeNow - adapterFlowTrendMonitorStartTime > 300 ? timeNow - 300 : adapterFlowTrendMonitorStartTime;
    long endWindow = timeNow - adapterFlowTrendMonitorStartTime > 300 ? timeNow : adapterFlowTrendMonitorStartTime + 300;

    adapterFlowTrendMapLock.lock();
    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {
        flowTrendData.insert(std::make_pair<>(adapterPipePair.first, std::map<long, long>()));

        // 从当前时间戳向前倒推300秒，构造map
        for (long t = startWindow; t <= endWindow; t++) {
            // 如果trafficPerSecond中存在该时间戳，则使用已有数据；否则填充为0
            if (adapterPipePair.second.flowTrendData.find(t) != adapterPipePair.second.flowTrendData.end()) {
                flowTrendData[adapterPipePair.first][t] = adapterPipePair.second.flowTrendData.at(t);
            }
            else {
                flowTrendData[adapterPipePair.first][t] = 0;
            }
        }
    }

    adapterFlowTrendMapLock.unlock();
}

// 获取指定数据包的详情内容
bool TsharkManager::getPacketDetailInfo(uint32_t frameNumber, rapidjson::Document& detailJson) {

    // 先通过editcap将这一帧数据包从文件中摘出来，然后再获取详情，这样会快一些
    std::string tmpFilePath = MiscUtil::getDefaultDataDir() + MiscUtil::getRandomString(10) + ".pcap";
    std::string splitCmd = editcapPath + " -r " + currentFilePath + " " + tmpFilePath + " " + std::to_string(frameNumber) + "-" + std::to_string(frameNumber);
    if (!ProcessUtil::Exec(splitCmd)) {
        LOG_F(ERROR, "Error in executing command: %s", splitCmd.c_str());
        remove(tmpFilePath.c_str());
        return false;
    }

    // 通过tshark获取指定数据包详细信息，输出格式为XML
    // 启动'tshark -r ${currentFilePath} -T pdml'命令，获取指定数据包的详情
    std::string cmd = tsharkPath + " -r " + tmpFilePath + " -T pdml";
    std::unique_ptr<FILE, decltype(&pclose)> pipe(ProcessUtil::PopenEx(cmd.c_str()), pclose);
    if (!pipe) {
        std::cout << "Failed to run tshark command." << std::endl;
        remove(tmpFilePath.c_str());
        return false;
    }

    // 读取tshark输出
    char buffer[8192] = { 0 };
    std::string tsharkResult;
    setvbuf(pipe.get(), NULL, _IOFBF, sizeof(buffer));
    int count = 0;
    while (fgets(buffer, sizeof(buffer) - 1, pipe.get()) != nullptr) {
        tsharkResult += buffer;
        memset(buffer, 0, sizeof(buffer));
    }

    remove(tmpFilePath.c_str());

    // 将xml内容转换为JSON
    if (!MiscUtil::xml2JSON(tsharkResult, detailJson)) {
        LOG_F(ERROR, "XML转JSON失败");
        return false;
    }

    // 字段翻译
    translator.translateShowNameFields(detailJson["pdml"]["packet"][0]["proto"], detailJson.GetAllocator());


    // 将原始十六进制数据插入进去
    if (detailJson.HasMember("pdml") && detailJson["pdml"].HasMember("packet")) {
        std::string packetHex;
        std::vector<unsigned char> packetData;
        if (getPacketHexData(frameNumber, packetData)) {
            // 将原始数据转换为16进制格式
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (unsigned char ch : packetData) {
                oss << std::setw(2) << static_cast<int>(ch);
            }
            packetHex = oss.str();
        }

        detailJson["pdml"]["packet"][0].AddMember(
            "hexdata",
            rapidjson::Value().SetString(packetHex.c_str(), detailJson.GetAllocator()),
            detailJson.GetAllocator()
        );

        // 去掉外层的键值
        rapidjson::Value temp;
        temp.CopyFrom(detailJson["pdml"]["packet"][0], detailJson.GetAllocator());
        detailJson.SetObject();
        detailJson.CopyFrom(temp, detailJson.GetAllocator());

        return true;
    }

    return false;
}

void TsharkManager::storageThreadEntry() {
    auto storageWork = [this]() {
        storeLock.lock();

        // 检查数据包列表是否有新的数据可供存储
        if (!packetsTobeStore.empty()) {
            storage->storePackets(packetsTobeStore);
            packetsTobeStore.clear();
        }

        // 检查会话列表是否有新的数据可供
        if (!sessionSetTobeStore.empty()) {
            storage->storeAndUpdateSessions(sessionSetTobeStore);
            sessionSetTobeStore.clear();
        }

        storeLock.unlock();
    };

    // 只要停止标记没有点亮，存储线程就要一直存在
    while (!stopFlag) {
        storageWork();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 稍等一下最后再执行一次，防止有遗漏的数据未入库
    std::this_thread::sleep_for(std::chrono::seconds(1));
    storageWork();
}

// 处理每一个数据包
void TsharkManager::processPacket(std::shared_ptr<Packet> packet) {

    // 将分析的数据包插入保存起来
    allPackets.insert(std::make_pair<>(packet->frame_number, packet));

    // 等待入库
    storeLock.lock();
    packetsTobeStore.push_back(packet);
    storeLock.unlock();

    if (packet->trans_proto == "TCP" || packet->trans_proto == "UDP") {

        // 创建五元组
        FiveTuple tuple{ packet->src_ip, packet->dst_ip, packet->src_port, packet->dst_port, packet->trans_proto };

        // 将数据包加入到相应会话的列表中，并更新统计信息
        std::shared_ptr<Session> session;
        if (sessionMap.find(tuple) == sessionMap.end()) {
            // 新的会话，初始化会话信息
            session = std::make_shared<Session>();
            session->session_id = sessionMap.size() + 1;        // 通过序号来分配ID
            session->ip1 = packet->src_ip;
            session->ip2 = packet->dst_ip;
            session->ip1_location = packet->src_location;
            session->ip2_location = packet->dst_location;
            session->ip1_port = packet->src_port;
            session->ip2_port = packet->dst_port;
            session->start_time = packet->time;
            session->end_time = packet->time;
            session->trans_proto = packet->trans_proto;
            if (packet->protocol != "TCP" && packet->protocol != "UDP") {
                session->app_proto = packet->protocol;
            }

            sessionMap.insert(std::make_pair(tuple, session));
            sessionIdMap[session->session_id] = session;
        }
        else {
            // 旧的会话，更新会话信息
            session = sessionMap[tuple];
            session->end_time = packet->time;
            if (packet->protocol != "TCP" && packet->protocol != "UDP") {
                session->app_proto = packet->protocol;
            }
        }

        // 共同的字段更新
        {
            session->packet_count++;
            session->total_bytes += packet->len;
            packet->belong_session_id = session->session_id;
        }

        // 统计双方的交互数据
        if (session->ip1 == packet->src_ip) {
            session->ip1_send_packets_count++;
            session->ip1_send_bytes_count += packet->len;
        }
        else {
            session->ip2_send_packets_count++;
            session->ip2_send_bytes_count += packet->len;
        }

        storeLock.lock();
        sessionSetTobeStore.insert(session);  // 将当前会话加入待存储集合
        storeLock.unlock();
    }
}

void TsharkManager::queryPackets(QueryCondition& queryConditon, std::vector<std::shared_ptr<Packet>>& packets, int& total) {
    storage->queryPackets(queryConditon, packets, total);
}

bool TsharkManager::convertToPcap(const std::string& inputFile, const std::string& outputFile) {
    // 构建 editcap 命令，将 pcapng 转换为 pcap 格式
    std::string command = editcapPath + " -F pcap " + inputFile + " " + outputFile;
    //std::cout << command.c_str() << std::endl;
    if (!ProcessUtil::Exec(command)) {
        LOG_F(ERROR, "Failed to convert to pcap format, command: %s", command.c_str());
        return false;
    }

    LOG_F(INFO, "Successfully converted %s to %s in pcap format", inputFile.c_str(), outputFile.c_str());
    return true;
}

WORK_STATUS TsharkManager::getWorkStatus() {
    std::unique_lock<std::recursive_mutex> lock(workStatusLock);
    return workStatus;
}

void TsharkManager::reset() {

    LOG_F(INFO, "reset called");

    // 如果还在抓包或者分析文件，将其停止
    if (workStatus == STATUS_CAPTURING) {
        stopCapture();
    }
    else if (workStatus == STATUS_MONITORING) {
        stopMonitorAdaptersFlowTrend();
    }

    workStatus = STATUS_IDLE;
    captureTsharkPid = 0;
    stopFlag = true;


    allPackets.clear();
    packetsTobeStore.clear();
    sessionMap.clear();
    sessionIdMap.clear();
    sessionSetTobeStore.clear();

    if (captureWorkThread) {
        captureWorkThread->join();
        captureWorkThread.reset();
    }
    if (storageThread) {
        storageThread->join();
        storageThread.reset();
    }

    // 删除之前的数据，重新开始
    LOG_F(INFO, "currentFilePath %s", currentFilePath.c_str());
    std::remove(currentFilePath.c_str());
    currentFilePath = "";

    // 重置数据库
    //storage->close();
    storage.reset();    // 析构旧的对象，关闭旧数据库文件的占用
    
    std::string dbFullPath = this->workDir + "/mytshark.db";
    // 重试删除
    for (int i = 0; i < 3; i++) {
        if (std::remove(dbFullPath.c_str()) == 0) {
            LOG_F(INFO, "Database deleted successfully");
            break;
        }
        else {
            LOG_F(ERROR, "Delete failed (attempt %d): %s", i, strerror(errno));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    storage = std::make_shared<TsharkDatabase>(dbFullPath);
}

void TsharkManager::printAllSessions() {
    for (auto& item : sessionMap) {
        rapidjson::Document doc(kObjectType);
        item.second->toJsonObj(doc, doc.GetAllocator());

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);

        // 打印JSON输出
        std::cout << buffer.GetString() << std::endl;
    }

}

void TsharkManager::querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList, int& total) {
    storage->querySessions(condition, sessionList, total);
}

bool TsharkManager::getIPStatsList(QueryCondition& condition, std::vector<std::shared_ptr<IPStatsInfo>>& ipStatsList, int& total) {
    return storage->queryIPStats(condition, ipStatsList, total);
}

// 获取协议统计列表
bool TsharkManager::getProtoStatsList(QueryCondition& condition,
    std::vector<std::shared_ptr<ProtoStatsInfo>>& protoStatsList,
    int& total) {
    return storage->queryProtoStats(condition, protoStatsList, total);
}

// 获取国家统计列表
bool TsharkManager::getCountryStatsList(QueryCondition& condition,
    std::vector<std::shared_ptr<CountryStatsInfo>>& countryStatsList,
    int& total) {
    return storage->queryCountryStats(condition, countryStatsList, total);
}

DataStreamCountInfo TsharkManager::getSessionDataStream(uint32_t sessionId, std::vector<DataStreamItem>& dataStreamList) {
    DataStreamCountInfo countInfo;
    if (sessionIdMap.find(sessionId) == sessionIdMap.end()) {
        LOG_F(ERROR, "session %d not found", sessionId);
        return countInfo;
    }

    std::shared_ptr<Session> session = sessionIdMap[sessionId];
    std::string transProto = session->trans_proto;

    // 把协议名称转换为小写
    std::transform(transProto.begin(), transProto.end(), transProto.begin(), ::tolower);

    // 四元组
    std::string fourTuple;
    if (session->ip1.find(":") != std::string::npos) {
        // IPv6的格式需要增加[]包起来
        fourTuple = "[" + session->ip1 + "]:" + std::to_string(session->ip1_port) + ",[" + session->ip2 + "]:" + std::to_string(session->ip2_port);
    }
    else {
        fourTuple = session->ip1 + ":" + std::to_string(session->ip1_port) + "," + session->ip2 + ":" + std::to_string(session->ip2_port);
    }

    // 准备tshark命令
    std::string tsharkCmd = tsharkPath + " -r " + currentFilePath + " -q -z follow," + transProto + ",raw," + fourTuple;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(ProcessUtil::PopenEx(tsharkCmd.c_str()), pclose);
    if (!pipe) {
        throw std::runtime_error("Failed to run tshark command.");
    }

    uint32_t maxItems = 500;
    // 逐行读取tshark输出
    std::vector<char> buffer(65535); // 应对巨型帧Jumbo Frame的情况
    bool dataStart = false;
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {

        std::string line(buffer.data());
        DataStreamItem item;

        MiscUtil::trimEnd(line);
        if (line.find("Node 0: ") == 0) {
            countInfo.node0 = line.substr(strlen("Node 0: "));
            continue;
        }
        if (line.find("Node 1: ") == 0) {
            countInfo.node1 = line.substr(strlen("Node 1: "));
            dataStart = true;
            continue;
        }

        if (!dataStart || line.find("=====") != std::string::npos) {
            continue;
        }

        if (line[0] == '\t') {
            item.hexData = line.substr(1);
            item.srcNode = countInfo.node1;
            item.dstNode = countInfo.node0;
            countInfo.node1PacketCount++;
            countInfo.node1BytesCount += (item.hexData.length() / 2);
        }
        else {
            item.hexData = line;
            item.srcNode = countInfo.node0;
            item.dstNode = countInfo.node1;
            countInfo.node0PacketCount++;
            countInfo.node0BytesCount += (item.hexData.length() / 2);
        }

        countInfo.totalPacketCount++;
        if (dataStreamList.size() < maxItems) {
            dataStreamList.push_back(item);
        }
    }

    return countInfo;
}

// 保存当前数据包
bool TsharkManager::savePacket(std::string savePath) {
    return MiscUtil::copyFile(currentFilePath, savePath);
}
