#include "ProcessUtil.h"
#include <fcntl.h>
#include <io.h>

#if defined(__unix__) || defined(__APPLE__)
FILE* ProcessUtil::PopenEx(std::string command, PID_T* pidOut) {
	int pipefd[2] = { 0 };
	FILE* pipeFp = nullptr;

	if (pipe(pipefd) == -1) {
		perror("pipe");
		return nullptr;
	}

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return nullptr;
    }

    if (pid == 0) {
        // 子进程
        close(pipefd[0]);  // 关闭读端
        dup2(pipefd[1], STDOUT_FILENO); // 将 stdout 重定向到管道
        dup2(pipefd[1], STDERR_FILENO); // 将 stderr 重定向到管道
        close(pipefd[1]);

        execl("/bin/sh", "sh", "-c", command.c_str(), NULL);  // 执行命令
        _exit(1);  // execl失败
    }

    // 父进程将读取管道，关闭写端
    close(pipefd[1]);
    pipeFp = fdopen(pipefd[0], "r");

    if (pidOut) {
        *pidOut = pid;
    }

    return pipeFp;
}    
int ProcessUtil::Kill(PID_T pid) {
    return kill(pid, SIGTERM);
}
#endif

#ifdef _WIN32
FILE* ProcessUtil::PopenEx(std::string command, PID_T* pidOut) {

    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES saAttr;
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFOA siStartInfo;
    FILE* pipeFp = nullptr;

    // 设置安全属性，允许管道句柄继承
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    // 创建匿名管道
    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
        perror("CreatePipe");
        return nullptr;
    }

    // 确保写句柄不被子进程继承
    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        perror("SetHandleInformation");
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return nullptr;
    }

    // 初始化 STARTUPINFO 结构体
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = hWritePipe;
    siStartInfo.hStdOutput = hWritePipe;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // 创建子进程
    if (!CreateProcessA(
        nullptr,                        // No module name (use command line)
        (LPSTR)command.data(),          // Command line
        nullptr,                        // Process handle not inheritable
        nullptr,                        // Thread handle not inheritable
        TRUE,                           // Set handle inheritance
        CREATE_NO_WINDOW,               // No window
        nullptr,                        // Use parent's environment block
        nullptr,                        // Use parent's starting directory 
        &siStartInfo,                   // Pointer to STARTUPINFO structure
        &piProcInfo                     // Pointer to PROCESS_INFORMATION structure
    )) {
        perror("CreateProcess");
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return nullptr;
    }

    // 关闭写端句柄（父进程不使用）
    CloseHandle(hWritePipe);

    // 返回子进程 PID
    if (pidOut) {
        *pidOut = piProcInfo.dwProcessId;
    }

    // 将管道的读端转换为 FILE* 并返回
    pipeFp = _fdopen(_open_osfhandle(reinterpret_cast<intptr_t>(hReadPipe), _O_RDONLY), "r");
    if (!pipeFp) {
        CloseHandle(hReadPipe);
    }

    // 关闭进程句柄（不需要等待子进程）
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

    return pipeFp;
}

int ProcessUtil::Kill(PID_T pid) {
    // 打开指定进程
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == nullptr) {
        std::cout << "Failed to open process with PID " << pid << ", error: " << GetLastError() << std::endl;
        return -1;
    }

    // 终止进程
    if (!TerminateProcess(hProcess, 0)) {
        std::cout << "Failed to terminate process with PID " << pid << ", error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    // 成功终止进程
    CloseHandle(hProcess);
    return 0;
}
#endif // _WIN32

bool ProcessUtil::Exec(std::string cmdline) {
#ifdef _WIN32
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFOA siStartInfo;

    // 初始化 STARTUPINFO 结构体
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));

    // 创建子进程
    if (CreateProcessA(
        nullptr,                        // No module name (use command line)
        (LPSTR)cmdline.data(),          // Command line
        nullptr,                        // Process handle not inheritable
        nullptr,                        // Thread handle not inheritable
        TRUE,                           // Set handle inheritance
        CREATE_NO_WINDOW,               // No window
        nullptr,                        // Use parent's environment block
        nullptr,                        // Use parent's starting directory
        &siStartInfo,                   // Pointer to STARTUPINFO structure
        &piProcInfo                     // Pointer to PROCESS_INFORMATION structure
    )) {
        WaitForSingleObject(piProcInfo.hProcess, INFINITE);
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);
        return true;
    }
    else {
        return false;
    }
#else
    return std::system(cmdline.c_str()) == 0;
#endif
}

std::string ProcessUtil::getExecutableDir() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);

    // 手动提取目录部分
    std::string exePath(path);
    size_t lastSlash = exePath.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        return exePath.substr(0, lastSlash);
    }
    return ".";  // 如果找不到路径分隔符，返回当前目录
}

bool ProcessUtil::isProcessRunning(PID_T pid) {
#ifdef _WIN32
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL) {
        return false;
    }
    DWORD exitCode;
    if (GetExitCodeProcess(process, &exitCode)) {
        CloseHandle(process);
        return (exitCode == STILL_ACTIVE);
    }
    CloseHandle(process);
    return false;
#else
    // On Unix-like systems, sending signal 0 to a process checks if it exists
    int ret = kill(pid, 0);
    return (ret == 0);
#endif
}
