#pragma once
#include<string>
#include "UrlParts.h";
class UrlValidator
{
public:
	UrlParts urlParser(std::string);
};