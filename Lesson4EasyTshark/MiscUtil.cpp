#include "MiscUtil.h"

std::string MiscUtil::getRandomString(size_t length) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    std::random_device rd;  // 用于种子
    std::mt19937 generator(rd());  // 生成器
    std::uniform_int_distribution<> distribution(0, chars.size() - 1);

    std::string randomString;
    for (size_t i = 0; i < length; ++i) {
        randomString += chars[distribution(generator)];
    }

    return randomString;
}

bool MiscUtil::xml2JSON(std::string xmlContent, Document& outJsonDoc) {
    // 解析 XML
    xml_document<> doc;
    try {
        doc.parse<0>(&xmlContent[0]);
    }
    catch (const rapidxml::parse_error& e) {
        std::cout << "XML Parsing error: " << e.what() << std::endl;
        return false;
    }

    // 创建 JSON 文档
    outJsonDoc.SetObject();
    Document::AllocatorType& allocator = outJsonDoc.GetAllocator();

    // 获取 XML 根节点
    xml_node<>* root = doc.first_node();
    if (root) {
        // 将根节点转换为 JSON
        Value root_json(kObjectType);
        xml_to_json_recursive(root_json, root, allocator);

        // 将根节点添加到 JSON 文档
        outJsonDoc.AddMember(Value(root->name(), allocator).Move(), root_json, allocator);
    }
    return true;
}

void MiscUtil::xml_to_json_recursive(Value& json, xml_node<>* node, Document::AllocatorType& allocator) {
    for (xml_node<>* cur_node = node->first_node(); cur_node; cur_node = cur_node->next_sibling()) {

        // 检查是否需要跳过节点
        xml_attribute<>* hide_attr = cur_node->first_attribute("hide");
        if (hide_attr && std::string(hide_attr->value()) == "yes") {
            continue;  // 如果 hide 属性值为 "true"，跳过该节点
        }

        // 检查是否已经有该节点名称的数组
        Value* array = nullptr;
        if (json.HasMember(cur_node->name())) {
            array = &json[cur_node->name()];
        }
        else {
            Value node_array(kArrayType); // 创建新的数组
            json.AddMember(Value(cur_node->name(), allocator).Move(), node_array, allocator);
            array = &json[cur_node->name()];
        }

        // 创建一个 JSON 对象代表当前节点
        Value child_json(kObjectType);

        // 处理节点的属性
        for (xml_attribute<>* attr = cur_node->first_attribute(); attr; attr = attr->next_attribute()) {
            Value attr_name(attr->name(), allocator);
            Value attr_value(attr->value(), allocator);
            child_json.AddMember(attr_name, attr_value, allocator);
        }

        // 递归处理子节点
        xml_to_json_recursive(child_json, cur_node, allocator);

        // 将当前节点对象添加到对应数组中
        array->PushBack(child_json, allocator);
    }
}

std::string MiscUtil::getDefaultDataDir() {
    static std::string dir = "";
    if (!dir.empty()) {
        return dir;
    }
#ifdef _WIN32
    dir = std::string(std::getenv("APPDATA")) + "\\easytshark\\";
#else
    dir = std::string(std::getenv("HOME")) + "/easytshark/";
#endif

    CreateDirectoryA(dir.c_str(), NULL);
    return dir;
    //return "D:/Code/c++/Lesson4EasyTshark/Lesson4EasyTshark/packets/";
}

bool MiscUtil::fileExists(const std::string& filePath) {
    struct stat buffer;
    return (stat(filePath.c_str(), &buffer) == 0);
}

std::string MiscUtil::getPcapNameByCurrentTimestamp(bool isFullPath) {
    // 获取当前时间
    std::time_t now = std::time(nullptr);
    std::tm* localTime = std::localtime(&now);

    // 格式化文件名
    char buffer[64];
    std::strftime(buffer, sizeof(buffer), "easytshark_%Y-%m-%d_%H-%M-%S.pcap", localTime);

    return isFullPath ? getDefaultDataDir() + std::string(buffer) : std::string(buffer);
}

// 将字符串按分隔符分割成字符串向量
std::vector<std::string> MiscUtil::splitString(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;

    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) {
            result.push_back(item);
        }
    }

    return result;
}

// 将字符串向量转换为整数向量
std::vector<int> MiscUtil::toIntVector(const std::vector<std::string>& strVec) {
    std::vector<int> result;
    result.reserve(strVec.size());

    for (const auto& str : strVec) {
        try {
            result.push_back(std::stoi(str));
        }
        catch (const std::exception& e) {
            // 转换失败时跳过或处理错误
            continue;
        }
    }

    return result;
}

