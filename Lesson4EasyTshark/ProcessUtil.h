#pragma once
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <loguru/loguru.hpp>

#ifdef _WIN32
typedef DWORD PID_T;
#else
typedef pid_t PID_T;
#endif


class ProcessUtil
{
public:
	static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr);
	static int Kill(PID_T pid);
	static bool Exec(std::string cmdline);
	static std::string getExecutableDir();
	static bool isProcessRunning(PID_T pid);
};

