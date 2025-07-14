#pragma once
#include <iostream>

class PageAndOrder
{
public:
    void reset() {
        pageNum = 0;
        pageSize = 0;
        orderBy = "";
        descOrAsc = "";
    }
    int pageNum = 0;
    int pageSize = 0;
    std::string orderBy;
    std::string descOrAsc;
};

