```
    std::string analysis_file;
    LOG_F(INFO, "请输入要分析的PCAP文件路径：");
    std::cin >> analysis_file;
    tsharkManager.analysisFile(analysis_file);
    tsharkManager.printAllPackets();

```

```
    LOG_F(INFO, "analysis completed, the total number of packets is: [%d]", allPackets.size());

    uint32_t number;
    LOG_F(INFO, "请输入要获取详情的数据包编号（1-%d）", allPackets.size());
    std::cin >> number;
    std::string res;
    if (!getPacketDetailInfo(number, res)) {
        LOG_F(ERROR, "获取详情失败");
        return;
    }
    //std::cout << res << std::endl;
    // 写入文件
    std::string jsonName = std::to_string(number) + "-" + std::to_string(allPackets.size()) + ".json";
    std::ofstream out(jsonName);
    out << res;
    out.close();

```

