#pragma once
#include "BaseController.h"
// 网卡相关的接口
class AdaptorController : public BaseController {
public:
    AdaptorController(httplib::Server& server, std::shared_ptr<TsharkManager> tsharkManager)
        :BaseController(server, tsharkManager)
    {
    }

    virtual void registerRoute() {

        __server.Get("/api/getNetworkAdapters", [this](const httplib::Request& req, httplib::Response& res) {
            getNetworkAdapters(req, res);
            });

        __server.Get("/api/getWorkStatus", [this](const httplib::Request& req, httplib::Response& res) {
            getWorkStatus(req, res);
            });

        __server.Post("/api/startCapture", [this](const httplib::Request& req, httplib::Response& res) {
            startCapture(req, res);
            });

        __server.Post("/api/stopCapture", [this](const httplib::Request& req, httplib::Response& res) {
            stopCapture(req, res);
            });

        __server.Get("/api/startMonitorAdaptersFlowTrend", [this](const httplib::Request& req, httplib::Response& res) {
            startMonitorAdaptersFlowTrend(req, res);
            });

        __server.Get("/api/stopMonitorAdaptersFlowTrend", [this](const httplib::Request& req, httplib::Response& res) {
            stopMonitorAdaptersFlowTrend(req, res);
            });

        __server.Get("/api/getAdaptersFlowTrendData", [this](const httplib::Request& req, httplib::Response& res) {
            getAdaptersFlowTrendData(req, res);
            });
    }

    void getWorkStatus(const httplib::Request& req, httplib::Response& res);

    void startCapture(const httplib::Request& req, httplib::Response& res);

    void stopCapture(const httplib::Request& req, httplib::Response& res);

    void startMonitorAdaptersFlowTrend(const httplib::Request& req, httplib::Response& res);

    void stopMonitorAdaptersFlowTrend(const httplib::Request& req, httplib::Response& res);

    void getAdaptersFlowTrendData(const httplib::Request& req, httplib::Response& res);

    void getNetworkAdapters(const httplib::Request& req, httplib::Response& res);
};

