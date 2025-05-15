#### 1. 工作在链路层的不会有IP地址，如ARP，LLDP协议
#### 2. 调试终端乱码
```
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#else
    setlocale(LC_ALL, "zh_CN.UTF-8");
#endif // _WIN32
```

#### 3. std::invalid_argument
某些数据包可能没有端口号（如 ICMP 或非 TCP/UDP 协议），这时 `tcp.srcport` 或 `tcp.dstport` 可能是空的。
`packet.src_port = fields[3].empty() ? 0 : std::stoll(fields[3]);`

#### 4. 作业代码
```
// Lesson4EasyTshark.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <vector>
#include <string>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

struct Packet
{
    int frame_number;
    std::string time;
    std::string src_ip;
    int src_port;
    std::string dst_ip;
    int dst_port;
    std::string protocol;
    std::string info;
};

void parseLine(std::string line, Packet& packet) {
    if (line.back() == '\n') {
        line.pop_back();
    }
    std::vector<std::string> fields;

    // 字符串拆分
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start));

    if (fields.size() >= 6) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.src_ip = fields[2];
        packet.src_port = fields[3].empty() ? 0 : std::stoll(fields[3]);  // 处理空字段
        packet.dst_ip = fields[4];
        packet.dst_port = fields[5].empty() ? 0 : std::stoll(fields[5]);
        packet.protocol = fields[6];
        packet.info = fields[7];
    }
}

void printPacket(const Packet& packet) {
    rapidjson::Document pktObj;
    rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();

    pktObj.SetObject();

    pktObj.AddMember("frame_number", packet.frame_number, allocator);
    pktObj.AddMember("timestamp", rapidjson::Value(packet.time.c_str(), allocator), allocator);
    pktObj.AddMember("src_ip", rapidjson::Value(packet.src_ip.c_str(), allocator), allocator);
    pktObj.AddMember("src_port", packet.src_port, allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_port", packet.dst_port, allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    std::cout << buffer.GetString() << std::endl;
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#else
    setlocale(LC_ALL, "zh_CN.UTF-8");
#endif // _WIN32

    const char* command = "D:/EdgeDownload/Wireshark/tshark.exe -r D:/Code/c++/Lesson4EasyTshark/packets.pcap -T fields -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e _ws.col.Protocol -e _ws.col.Info";

    FILE* pipe = _popen(command, "r");
    if (!pipe) {
        std::cerr << "Failed to run tshark command!" << std::endl;
        return 1;
    }

    std::vector<Packet> packets;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;
        parseLine(buffer, packet);
        packets.push_back(packet);
    }
    
    //for (auto& p : packets) {
    //    printf("frame_number: %d  time: %s  src_ip: %s  dst_ip: %s  protocol: %s  info: %s\n",
    //        p.frame_number,
    //        p.time.c_str(),
    //        p.src_ip.c_str(),
    //        p.dst_ip.c_str(),
    //        p.protocol.c_str(),
    //        p.info.c_str());
    //}

    for (auto& p : packets) {
        printPacket(p);
    }

    _pclose(pipe);
    return 0;
}

```

