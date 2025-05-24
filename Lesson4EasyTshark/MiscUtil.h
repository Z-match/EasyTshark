#pragma once
#include <random>
#include <string>
#include <fstream>
#include <sstream>
#include <rapidxml/rapidxml.hpp>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <iostream>

using namespace rapidxml;
using namespace rapidjson;

class MiscUtil
{
public:
	static std::string getRandomString(size_t length);
	// 将XML转为JSON格式
	static bool xml2JSON(std::string xmlContent, Document& outJsonDoc);
	static std::string getDefaultDataDir();
private:
	static void xml_to_json_recursive(Value& json, xml_node<>* node, Document::AllocatorType& allocator);

};

