#pragma once
#include <map>
#include <string>
#include "rapidjson/document.h"

class Traslator {
public:
    // �ݹ鷭�� showname �ֶ�
    void translateShowNameFields(rapidjson::Value& value, rapidjson::Document::AllocatorType& allocator) {
        // ����Ƕ��󣬼�鲢���� showname �ֶ�
        if (value.IsObject()) {
            if (value.HasMember("showname") && value["showname"].IsString()) {
                std::string showname = value["showname"].GetString();

                // ���� translationMap ���Ҿ�̬���ֲ��滻
                for (const auto& pair : translationMap) {
                    const std::string& key = pair.first;
                    const std::string& translation = pair.second;

                    // ����ֶ�A���Ƿ����translationMap�е�key����̬���֣�
                    if (showname.find(key) == 0) {
                        // �滻��̬����
                        showname.replace(0, key.length(), translation);
                        value["showname"].SetString(showname.c_str(), allocator);
                        break;
                    }
                }
            }
            else if (value.HasMember("show") && value["show"].IsString()) {
                std::string showname = value["show"].GetString();

                // ���� translationMap ���Ҿ�̬���ֲ��滻
                for (const auto& pair : translationMap) {
                    const std::string& key = pair.first;
                    const std::string& translation = pair.second;

                    // ����ֶ�A���Ƿ����translationMap�е�key����̬���֣�
                    if (showname.find(key) == 0) {
                        // �滻��̬����
                        showname.replace(0, key.length(), translation);
                        value["show"].SetString(showname.c_str(), allocator);
                        break;
                    }
                }
            }

            // ����� "field" �ֶΣ��ݹ鴦��
            if (value.HasMember("field") && value["field"].IsArray()) {
                // ֱ������ "field" �����е�ÿ��Ԫ�ؽ��еݹ鷭��
                rapidjson::Value& fieldArray = value["field"];
                for (auto& field : fieldArray.GetArray()) {
                    translateShowNameFields(field, allocator);  // �ݹ鴦��ÿ�� field
                }
            }
        }
        // ��������飬�ݹ����ÿ��Ԫ��
        else if (value.IsArray()) {
            for (auto& item : value.GetArray()) {
                translateShowNameFields(item, allocator);  // �ݹ鴦��ÿ��Ԫ��
            }
        }
    }

private:
    std::map<std::string, std::string> translationMap = {
    {"General information", "������Ϣ"},
    {"Frame Number", "֡���"},
    {"Captured Length", "���񳤶�"},
    {"Captured Time", "����ʱ��"},
    {"Section number", "�ں�"},
    {"Interface id", "�ӿ� id"},
    {"Interface name", "�ӿ�����"},
    {"Encapsulation type", "��װ����"},
    {"Arrival Time", "����ʱ��"},
    {"UTC Arrival Time", "UTC����ʱ��"},
    {"Epoch Arrival Time", "��Ԫ����ʱ��"},
    {"Time shift for this packet", "�����ݰ���ʱ��ƫ��"},
    {"Time delta from previous captured frame", "����һ������֡��ʱ���"},
    {"Time delta from previous displayed frame", "����һ����ʾ֡��ʱ���"},
    {"Time since reference or first frame", "�Բο�֡���һ֡������ʱ��"},
    {"Frame Number", "֡���"},
    {"Frame Length", "֡����"},
    {"Capture Length", "���񳤶�"},
    {"Frame is marked", "֡���"},
    {"Frame is ignored", "֡����"},
    {"Frame", "֡"},
    {"Protocols in frame", "֡�е�Э��"},
    {"Ethernet II", "��̫�� II"},
    {"Destination", "Ŀ�ĵ�ַ"},
    {"Address Resolution Protocol", "ARP��ַ������ַ"},
    {"Address (resolved)", "��ַ��������"},
    {"Type", "����"},
    {"Stream index", "������"},
    {"Internet Protocol Version 4", "������Э��汾 4"},
    {"Internet Protocol Version 6", "������Э��汾 6"},
    {"Internet Control Message Protocol", "������������ϢЭ��ICMP"},
    {"Version", "�汾"},
    {"Header Length", "ͷ������"},
    {"Differentiated Services Field", "��ַ����ֶ�"},
    {"Total Length", "�ܳ���"},
    {"Identification", "��ʶ��"},
    {"Flags", "��־"},
    {"Time to Live", "����ʱ��"},
    {"Transmission Control Protocol", "TCP�������Э��"},
    {"User Datagram Protocol", "UDP�û����ݰ�Э��"},
    {"Domain Name System", "DNS��������ϵͳ"},
    {"Header Checksum", "ͷ��У���"},
    {"Header checksum status", "У���״̬"},
    {"Source Address", "Դ��ַ"},
    {"Destination Address", "Ŀ�ĵ�ַ"},
    {"Source Port", "Դ�˿�"},
    {"Destination Port", "Ŀ�Ķ˿�"},
    {"Next Sequence Number", "��һ�����к�"},
    {"Sequence Number", "���к�"},
    {"Acknowledgment Number", "ȷ�Ϻ�"},
    {"Acknowledgment number", "ȷ�Ϻ�"},
    {"TCP Segment Len", "TCP�γ���"},
    {"Conversation completeness", "�Ự������"},
    {"Window size scaling factor", "������������"},
    {"Calculated window size", "���㴰�ڴ�С"},
    {"Window", "����"},
    {"Urgent Pointer", "����ָ��"},
    {"Checksum:", "У���:"},
    {"TCP Option - Maximum segment size", "TCPѡ�� - ���δ�С"},
    {"Kind", "����"},
    {"MSS Value", "MSSֵ"},
    {"TCP Option - Window scale", "TCPѡ�� - ��������"},
    {"Shift count", "��λ����"},
    {"Multiplier", "����"},
    {"TCP Option - Timestamps", "TCPѡ�� - ʱ���"},
    {"TCP Option - SACK permitted", "TCPѡ�� - SACK ����"},
    {"TCP Option - End of Option List", "TCPѡ�� - ѡ���б����"},
    {"Options", "ѡ��"},
    {"TCP Option - No-Operation", "TCPѡ�� - �޲���"},
    {"Timestamps", "ʱ���"},
    {"Time since first frame in this TCP stream", "�Ե�һ֡������ʱ��"},
    {"Time since previous frame in this TCP stream", "����һ��֡��ʱ���"},
    {"Protocol:", "Э��:"},
    {"Source:", "Դ��ַ:"},
    {"Length:", "����:"},
    {"Checksum status", "У���״̬"},
    {"Checksum Status", "У���״̬"},
    {"TCP payload", "TCP�غ�"},
    {"UDP payload", "UDP�غ�"},
    {"Hypertext Transfer Protocol", "���ı�����Э��HTTP"},
    {"Transport Layer Security", "����㰲ȫЭ��TLS"}
    };
};