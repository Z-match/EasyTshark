#include "TsharkError.h"

std::map<int, std::string> TsharkError::ERROR_MSG_MAP = {
        {ERROR_SUCCESS, "操作成功"},
        {ERROR_PARAMETER_WRONG, "参数错误"},
        {ERROR_INTERNAL_WRONG, "内部错误"},
        {ERROR_DATABASE_WRONG, "数据库错误"},
        {ERROR_TSHARK_WRONG, "tshark执行错误"},
        {ERROR_STATUS_WRONG, "状态错误"},
        {ERROR_FILE_TOOLARGE, "文件太大了"},
        {ERROR_FILE_NOTFOUND, "文件不存在"}
};
