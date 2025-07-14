#include "TsharkManager.h"
#include <WinSock2.h>
#include <Windows.h>
#include "ProcessUtil.h"
#include "PacketController.h"
#include <httplib/httplib.h>
#include "AdaptorController.h"
#include "SessionController.h"
#include "StatsController.h"

void Initlog(int argc, char* argv[]) {
    loguru::init(argc, argv);
    loguru::add_file("logs.txt", loguru::Append, loguru::Verbosity_MAX);
}

httplib::Server::HandlerResponse before_request(const httplib::Request& req, httplib::Response& res) {
    LOG_F(INFO, "Request received for %s", req.path.c_str());

    // 提取分页参数
    PageAndOrder* pageAndOrder = PageHelper::getPageAndOrder();
    pageAndOrder->pageNum = BaseController::getIntParam(req, "pageNum", 1);
    pageAndOrder->pageSize = BaseController::getIntParam(req, "pageSize", 100);
    pageAndOrder->orderBy = BaseController::getStringParam(req, "orderBy", "");
    pageAndOrder->descOrAsc = BaseController::getStringParam(req, "descOrAsc", "asc");
    return httplib::Server::HandlerResponse::Unhandled;
}

void after_response(const httplib::Request& req, httplib::Response& res) {
    if (req.method != "OPTIONS") {
        res.set_header("Access-Control-Allow-Origin", "http://localhost:3000");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.set_header("Access-Control-Allow-Credentials", "true");
    }
    LOG_F(INFO, "Received response with status %d", res.status);
}

int main(int argc, char* argv[]) {

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#else
    setlocale(LC_ALL, "zh_CN.UTF-8");
#endif // _WIN32

    Initlog(argc, argv);

    // 提取UI进程参数
    std::string paramName = "--uipid=";
    if (argc < 2 || strstr(argv[1], paramName.c_str()) == nullptr) {
        LOG_F(ERROR, "usage: tshark_server --uipid=xxx");
        return -1;
    }

    std::string pidParam = argv[1];
    auto pos1 = pidParam.find(paramName) + paramName.size();
    auto pos2 = pidParam.find(" ", pos1);
    PID_T pid = std::stoi(pidParam.substr(pos1, pos2));
    if (!ProcessUtil::isProcessRunning(pid)) {
        LOG_F(ERROR, "UI进程不存在，tshark_server将退出");
        return -1;
    }

    // 启动UI监控线程
    std::thread uiMonitorThread([&]() {
        while (true) {
            if (!ProcessUtil::isProcessRunning(pid)) {
                LOG_F(INFO, "检测到UI进程已退出");
                return;
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        });

    std::string currentExePath = ProcessUtil::getExecutableDir();
    std::cout << currentExePath << std::endl;
    auto tsharkManager = std::make_shared<TsharkManager>(currentExePath);
    httplib::Server server;
    server.Options(".*", [](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "http://localhost:3000");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.set_header("Access-Control-Allow-Credentials", "true");
        res.status = 200;
        });
    //auto tsharkManager = std::make_shared<TsharkManager>("D:/Code/c++/Lesson4EasyTshark/Lesson4EasyTshark/");
    //tsharkManager->analysisFile("D:/Code/c++/Lesson4EasyTshark/Lesson4EasyTshark/capture.pcap");
    //tsharkManager->printAllSessions();

    // 创建Controller并注册路由
    std::vector<std::shared_ptr<BaseController>> controllerList;
    controllerList.push_back(std::make_shared<PacketController>(server, tsharkManager));
    controllerList.push_back(std::make_shared<SessionController>(server, tsharkManager));
    controllerList.push_back(std::make_shared<AdaptorController>(server, tsharkManager));
    controllerList.push_back(std::make_shared<StatsController>(server, tsharkManager));

    for (auto controller : controllerList) {
        controller->registerRoute();
    }

    server.set_pre_routing_handler(before_request);
    server.set_post_routing_handler(after_response);

    // 启动服务器
    // 在另一个线程中启动HTTP服务
    std::thread serverThread([&]() {
        LOG_F(INFO, "tshark_server is running on http://127.0.0.1:8080");
        server.listen("127.0.0.1", 8080);
        });


    // 等待UI进程退出
    uiMonitorThread.join();

    // UI进程退出后，HTTP服务即关闭
    server.stop();
    serverThread.join();

    // 如果还在抓包或者监控网卡流量，将其关闭
    tsharkManager->reset();

    return 0;
}

