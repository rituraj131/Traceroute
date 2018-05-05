#pragma once
#include<string>
class UrlParts {
public:
	std::string url;
	int port_no;
	std::string host, scheme, query, path;
	int isValid;
};