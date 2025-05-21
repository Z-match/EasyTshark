#pragma once
#include <iostream>
#include <map>
#include <thread>
#include <Windows.h>

#ifdef _WIN32
typedef DWORD PID_T;
#else
typedef pid_t PID_T;
#endif

class AdapterMonitorInfo
{
public:
    AdapterMonitorInfo() {
        monitorTsharkPipe = nullptr;
        tsharkPid = 0;
    }
    std::string adapterName;                            // ��������
    std::map<long, long> flowTrendData;                 // ������������
    std::shared_ptr<std::thread> monitorThread;         // �����ظ�����������߳�
    FILE* monitorTsharkPipe;                            // �߳���tsharkͨ�ŵĹܵ�
    PID_T tsharkPid;                                    // ���𲶻���������ݵ�tshark����PID
};

