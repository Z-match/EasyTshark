#pragma once
#include <random>
#include <string>
#include <fstream>
#include <sstream>
#include <rapidxml/rapidxml.hpp>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <iostream>
#include <sys/stat.h>
#include <set>
#include <vector>
#include <Windows.h>

using namespace rapidxml;
using namespace rapidjson;

class MiscUtil
{
public:
    static std::string getRandomString(size_t length);
    // 将XML转为JSON格式
    static bool xml2JSON(std::string xmlContent, Document& outJsonDoc);
    static std::string getDefaultDataDir();
    // 检查文件是否存在
    static bool fileExists(const std::string& filePath);
    // 通过当前时间戳获取一个pcap文件名
    static std::string getPcapNameByCurrentTimestamp(bool isFullPath = true);
    // 将字符串按分隔符分割成字符串向量
    static std::vector<std::string> splitString(const std::string& str, char delimiter);
    // 将字符串向量转换为整数向量
    static std::vector<int> toIntVector(const std::vector<std::string>& strVec);

    // 将集合转换为字符串
    template<typename T>
    static std::string convertSetToString(const std::set<T>& inputSet, char delimiter) {
        std::string result;
        for (const auto& item : inputSet) {
            if (!result.empty()) {
                result += delimiter;
            }
            result += std::to_string(item);
        }
        return result;
    }

    // 特化版本处理字符串类型的集合
    template<>
    static std::string convertSetToString<std::string>(const std::set<std::string>& inputSet, char delimiter) {
        std::string result;
        for (const auto& item : inputSet) {
            if (!result.empty()) {
                result += delimiter;
            }
            result += item;
        }
        return result;
    }

    // 将向量转换为集合
    template<typename T>
    static std::set<T> toSet(const std::vector<T>& inputVec) {
        return std::set<T>(inputVec.begin(), inputVec.end());
    }

    // 去除字符串末尾的空白字符
    static void trimEnd(std::string& str) {
        if (str.empty()) return;

        size_t end = str.length();
        while (end > 0 && std::isspace(static_cast<unsigned char>(str[end - 1]))) {
            --end;
        }

        str.resize(end);
    }

    static bool copyFile(const std::string& source, const std::string& destination) {
#ifdef _WIN32
        // 将多字节字符串转换为宽字符字符串
        std::wstring wsource(source.begin(), source.end());
        std::wstring wdestination(destination.begin(), destination.end());
        // Windows 系统使用 CopyFile 函数
        return CopyFileW(wsource.c_str(), wdestination.c_str(), FALSE);
#else
        // POSIX 系统使用 open/read/write 进行拷贝
        int src = open(source.c_str(), O_RDONLY);
        if (src < 0) return false;

        int dest = open(destination.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dest < 0) {
            close(src);
            return false;
        }

        char buffer[4096];
        ssize_t bytesRead;
        while ((bytesRead = read(src, buffer, sizeof(buffer))) > 0) {
            write(dest, buffer, bytesRead);
        }

        close(src);
        close(dest);
        return true;
#endif
    }


private:
    static void xml_to_json_recursive(Value& json, xml_node<>* node, Document::AllocatorType& allocator);
};