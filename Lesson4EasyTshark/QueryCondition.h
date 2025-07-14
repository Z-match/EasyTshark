#pragma once
#include <iostream>
#include <vector>
class QueryCondition
{
public:
	std::string mac;
	std::string ip;
	uint16_t port = 0;
	std::string location;
	std::string proto;
	double startTime = 0;
	double endTime = 0;
	std::vector<std::string> protocols;
	std::string sortField = "total_sent_bytes"; // 默认排序字段
	std::string sortOrder = "DESC";             // 默认排序顺序
	int pageNum = 1;
	int pageSize = 100;
	uint32_t session_id = 0;
};

