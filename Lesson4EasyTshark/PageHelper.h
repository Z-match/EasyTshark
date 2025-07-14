#pragma once
#include "PageAndOrder.h"
#include <sstream>

class PageHelper
{
public:
    static PageAndOrder* getPageAndOrder() {
        return &pageAndOrder;
    }

    static std::string getPageSql() {
        std::stringstream ss;
        if (!pageAndOrder.orderBy.empty()) {
            ss << " ORDER BY " << pageAndOrder.orderBy << " " << pageAndOrder.descOrAsc;
        }
        int offset = (pageAndOrder.pageNum - 1) * pageAndOrder.pageSize;
        ss << " LIMIT " << pageAndOrder.pageSize << " OFFSET " << offset << ";";

        return ss.str();
    }

private:
    static thread_local PageAndOrder pageAndOrder;
};

