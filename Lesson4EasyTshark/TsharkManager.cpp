#include "TsharkManager.h"
TsharkManager::TsharkManager(std::string workDir) {
    this->tsharkPath = "D:/EdgeDownload/Wireshark/tshark.exe";
    std::string xdbPath = workDir + "/third_library/ip2region/ip2region.xdb";
    ip2RegionUtil.init(xdbPath);
}

TsharkManager::~TsharkManager() {
    //ip2RegionUtil.uninit();
}

bool TsharkManager::analysisFile(std::string filePath) {

    std::vector<std::string> tsharkArgs = {
            tsharkPath,
            "-r", filePath,
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

    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return false;
    }

    char buffer[4096];

    // 当前处理的报文在文件中的偏移，第一个报文的偏移就是全局文件头24(也就是sizeof(PcapHeader))字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet)) {
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

        // 将分析的数据包插入保存起来
        allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }

    _pclose(pipe);

    // 记录当前分析的文件路径
    currentFilePath = filePath;

    return true;
}

bool TsharkManager::parseLine(std::string line, std::shared_ptr<Packet> packet) {
    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    // 自己实现字符串拆分
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
    // 10: tcp.srcport
    // 11: udp.srcport
    // 12: tcp.dstport
    // 13: udp.dstport
    // 14: _ws.col.Protocol
    // 15: _ws.col.Info

    if (fields.size() >= 16) {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = fields[1];
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];
        if (!fields[10].empty() || !fields[11].empty()) {
            packet->src_port = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }

        if (!fields[12].empty() || !fields[13].empty()) {
            packet->dst_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
        packet->protocol = fields[14];
        packet->info = fields[15];

        return true;
    }
    else {
        return false;
    }
}

std::string TsharkManager::epoch_to_formatted(double epoch_time) {
    // 分离整数秒和小数秒
    time_t seconds = static_cast<time_t>(epoch_time);
    double fractional = epoch_time - seconds;
    int microseconds = static_cast<int>(round(fractional * 1'000'000));

    // 转换为本地时间
    struct tm tm;
    localtime_s(&tm, &seconds);

    // 格式化输出
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << "." << std::setfill('0') << std::setw(6) << microseconds;

    return oss.str();
}

void TsharkManager::printAllPackets() {

    for (auto pair : allPackets) {

        std::shared_ptr<Packet> packet = pair.second;

        // 构建JSON对象
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator); 
        pktObj.AddMember("timestamp", rapidjson::Value(epoch_to_formatted(std::stod(packet->time)).c_str(), allocator), allocator);
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

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);

        // 打印JSON输出
        std::cout << buffer.GetString() << std::endl;

        //// 读取这个报文的原始十六进制数据
        //std::vector<unsigned char> data;
        //getPacketHexData(packet->frame_number, data);
        //// 打印读取到的数据：
        //printf("Packet Hex: ");
        //for (unsigned char byte : data) {
        //    printf("%02X ", byte);
        //}
        //printf("\n\n");

    }
}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data) {
    std::ifstream file(currentFilePath, std::ios::binary);
    if (!file) {
        std::cerr << "无法打开文件！\n";
        return false;
    }

    // 定位到指定偏移量
    file.seekg(allPackets[frameNumber]->file_offset, std::ios::beg);

    // 读取指定长度的数据
    uint32_t length = allPackets[frameNumber]->cap_len;
    data.resize(length);
    file.read(reinterpret_cast<char*>(data.data()), length);

    file.close();
    return true;

}
