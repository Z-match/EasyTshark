#include "TsharkManager.h"
#include <Windows.h>


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

    return 0;
}



//#include <iostream>
//#include <fstream>
//#include <Windows.h>
//#include <vector>
//#include <string>
//#include "rapidjson/document.h"
//#include "rapidjson/writer.h"
//#include "rapidjson/prettywriter.h"
//#include "rapidjson/stringbuffer.h"
//#include "ip2region_util.h"
//
//struct Packet
//{
//    int frame_number;
//    std::string time;
//    uint32_t cap_len;
//    std::string src_ip;
//    std::string src_location;
//    int src_port;
//    std::string dst_ip;
//    std::string dst_location;
//    int dst_port;
//    std::string protocol;
//    std::string info;
//    uint32_t file_offset;
//};
//
//// PCAP全局文件头
//struct PcapHeader {
//	uint32_t magic_number;
//	uint16_t version_major;
//	uint16_t version_minor;
//	int32_t thisZone;
//	uint32_t sigfigs;
//	uint32_t snaplen;
//	uint32_t network;
//};
//
//// 每一个数据报文前面的头
//struct PacketHeader {
//	uint32_t ts_sec;
//	uint32_t ts_usec;
//	uint32_t caplen;
//	uint32_t len;
//};
//
//void parseLine(std::string line, Packet& packet, IP2RegionUtil& locationUtil) {
//    if (line.back() == '\n') {
//        line.pop_back();
//    }
//    std::vector<std::string> fields;
//
//    // 字符串拆分
//    size_t start = 0, end;
//    while ((end = line.find('\t', start)) != std::string::npos) {
//        fields.push_back(line.substr(start, end - start));
//        start = end + 1;
//    }
//    fields.push_back(line.substr(start));
//
//    // 字段顺序：-e frame.number -e frame.time -e frame.cap_len -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst
//    // -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info
//    // 0: frame.number
//    // 1: frame.time
//    // 2: frame.cap_len
//    // 3: ip.src
//    // 4: ipv6.src
//    // 5: ip.dst
//    // 6: ipv6.dst
//    // 7: tcp.srcport
//    // 8: udp.srcport
//    // 9: tcp.dstport
//    // 10: udp.dstport
//    // 11: _ws.col.Protocol
//    // 12: _ws.col.Info
//
//    if (fields.size() >= 13) {
//        packet.frame_number = std::stoi(fields[0]);
//        packet.time = fields[1];
//        packet.cap_len = std::stoi(fields[2]);
//        packet.src_ip = fields[3].empty() ? fields[4] : fields[3];
//        packet.dst_ip = fields[5].empty() ? fields[6] : fields[5];
//        packet.src_location = locationUtil.getIpLocation(packet.src_ip);
//        packet.dst_location = locationUtil.getIpLocation(packet.dst_ip);
//        if (!fields[7].empty() || !fields[8].empty()) {
//            packet.src_port = std::stoi(fields[7].empty() ? fields[8] : fields[7]);
//        }
//
//        if (!fields[9].empty() || !fields[10].empty()) {
//            packet.dst_port = std::stoi(fields[9].empty() ? fields[10] : fields[9]);
//        }
//        packet.protocol = fields[11];
//        packet.info = fields[12];
//    }
//}
//
//void printPacket(const Packet& packet) {
//    rapidjson::Document pktObj;
//    rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();
//
//    pktObj.SetObject();
//
//    pktObj.AddMember("frame_number", packet.frame_number, allocator);
//    pktObj.AddMember("timestamp", rapidjson::Value(packet.time.c_str(), allocator), allocator);
//    pktObj.AddMember("src_ip", rapidjson::Value(packet.src_ip.c_str(), allocator), allocator);
//    pktObj.AddMember("src_location", rapidjson::Value(packet.src_location.c_str(), allocator), allocator);
//    pktObj.AddMember("src_port", packet.src_port, allocator);
//    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
//    pktObj.AddMember("dst_location", rapidjson::Value(packet.dst_location.c_str(), allocator), allocator);
//    pktObj.AddMember("dst_port", packet.dst_port, allocator);
//    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
//    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);
//    pktObj.AddMember("file_offset", packet.file_offset, allocator);
//    pktObj.AddMember("cap_len", packet.cap_len, allocator);
//
//    rapidjson::StringBuffer buffer;
//    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
//    pktObj.Accept(writer);
//
//    std::cout << buffer.GetString() << std::endl;
//}
//
//bool readPacketHex(const std::string& filePath, uint32_t offset, uint32_t length, std::vector<unsigned char>& buffer) {
//    std::ifstream file(filePath, std::ios::binary);
//    if (!file) {
//        std::cerr << "无法打开文件！\n";
//        return false;
//    }
//
//    // 定位到指定偏移量
//    file.seekg(offset, std::ios::beg);
//
//    // 读取指定长度的数据
//    buffer.resize(length);
//    file.read(reinterpret_cast<char*>(buffer.data()), length);
//
//    file.close();
//    return true;
//}
//
//int main()
//{
//#ifdef _WIN32
//    SetConsoleOutputCP(CP_UTF8);
//#else
//    setlocale(LC_ALL, "zh_CN.UTF-8");
//#endif // _WIN32
//
//    std::string packet_file = "D:/Code/c++/Lesson4EasyTshark/packets.pcap";
//    std::string command = "D:/EdgeDownload/Wireshark/tshark.exe -r " + packet_file + " -T fields -e frame.number -e frame.time -e frame.cap_len -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e _ws.col.Info";
//
//    IP2RegionUtil ip2RegionUtil;
//    ip2RegionUtil.init("D:/Code/c++/Lesson4EasyTshark/Lesson4EasyTshark/third_library/ip2region/ip2region.xdb");
//
//    FILE* pipe = _popen(command.c_str(), "r");
//    if (!pipe) {
//        std::cerr << "Failed to run tshark command!" << std::endl;
//        return 1;
//    }
//
//    std::vector<Packet> packets;
//    char buffer[4096];
//    uint32_t file_offset = sizeof(PcapHeader);
//    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
//        Packet packet;
//        parseLine(buffer, packet, ip2RegionUtil);
//
//        packet.file_offset = file_offset + sizeof(PacketHeader);
//        file_offset = file_offset + sizeof(PacketHeader) + packet.cap_len;
//
//        packets.push_back(packet);
//    }
//    
//    for (auto& p : packets) {
//        printPacket(p);
//
//        // 读取这个报文的原始十六进制数据
//        std::vector<unsigned char> buffer;
//        readPacketHex(packet_file, p.file_offset, p.cap_len, buffer);
//
//        // 打印读取到的数据：
//        printf("Packet Hex: ");
//        for (unsigned char byte : buffer) {
//            printf("%02X ", byte);
//        }
//        printf("\n\n");
//    }
//
//    _pclose(pipe);
//    return 0;
//}
