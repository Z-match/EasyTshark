#include "MiscUtil.h"

std::string MiscUtil::getRandomString(size_t length) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    std::random_device rd;  // ��������
    std::mt19937 generator(rd());  // ������
    std::uniform_int_distribution<> distribution(0, chars.size() - 1);

    std::string randomString;
    for (size_t i = 0; i < length; ++i) {
        randomString += chars[distribution(generator)];
    }

    return randomString;
}

bool MiscUtil::xml2JSON(std::string xmlContent, Document& outJsonDoc) {
    // ���� XML
    xml_document<> doc;
    try {
        doc.parse<0>(&xmlContent[0]);
    }
    catch (const rapidxml::parse_error& e) {
        std::cout << "XML Parsing error: " << e.what() << std::endl;
        return false;
    }

    // ���� JSON �ĵ�
    outJsonDoc.SetObject();
    Document::AllocatorType& allocator = outJsonDoc.GetAllocator();

    // ��ȡ XML ���ڵ�
    xml_node<>* root = doc.first_node();
    if (root) {
        // �����ڵ�ת��Ϊ JSON
        Value root_json(kObjectType);
        xml_to_json_recursive(root_json, root, allocator);

        // �����ڵ���ӵ� JSON �ĵ�
        outJsonDoc.AddMember(Value(root->name(), allocator).Move(), root_json, allocator);
    }
    return true;
}

void MiscUtil::xml_to_json_recursive(Value& json, xml_node<>* node, Document::AllocatorType& allocator) {
    for (xml_node<>* cur_node = node->first_node(); cur_node; cur_node = cur_node->next_sibling()) {

        // ����Ƿ���Ҫ�����ڵ�
        xml_attribute<>* hide_attr = cur_node->first_attribute("hide");
        if (hide_attr && std::string(hide_attr->value()) == "yes") {
            continue;  // ��� hide ����ֵΪ "true"�������ýڵ�
        }

        // ����Ƿ��Ѿ��иýڵ����Ƶ�����
        Value* array = nullptr;
        if (json.HasMember(cur_node->name())) {
            array = &json[cur_node->name()];
        }
        else {
            Value node_array(kArrayType); // �����µ�����
            json.AddMember(Value(cur_node->name(), allocator).Move(), node_array, allocator);
            array = &json[cur_node->name()];
        }

        // ����һ�� JSON �������ǰ�ڵ�
        Value child_json(kObjectType);

        // ����ڵ������
        for (xml_attribute<>* attr = cur_node->first_attribute(); attr; attr = attr->next_attribute()) {
            Value attr_name(attr->name(), allocator);
            Value attr_value(attr->value(), allocator);
            child_json.AddMember(attr_name, attr_value, allocator);
        }

        // �ݹ鴦���ӽڵ�
        xml_to_json_recursive(child_json, cur_node, allocator);

        // ����ǰ�ڵ������ӵ���Ӧ������
        array->PushBack(child_json, allocator);
    }
}

std::string MiscUtil::getDefaultDataDir() {
    return "D:/Code/c++/Lesson4EasyTshark/Lesson4EasyTshark/packets/";
}
