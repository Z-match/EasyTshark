#pragma once
#include "tshark_datatype.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
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

class TsharkManager
{
public:
    TsharkManager(std::string workDir);
    ~TsharkManager();

    // �������ݰ��ļ�
    bool analysisFile(std::string filePath);

    // ��ӡ�������ݰ�����Ϣ
    void printAllPackets();

    // ��ȡָ��������ݰ���ʮ����������
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

private:
    // ����ÿһ��
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

private:

    std::string tsharkPath;
    IP2RegionUtil ip2RegionUtil;

    // ��ǰ�������ļ�·��
    std::string currentFilePath;

    // �����õ����������ݰ���Ϣ��key�����ݰ�ID��value�����ݰ���Ϣָ�룬������ݱ�Ż�ȡָ�����ݰ���Ϣ
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
};

