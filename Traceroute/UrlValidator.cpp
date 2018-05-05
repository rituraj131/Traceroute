#include "UrlValidator.h"
#include <iostream>
using namespace std;

size_t getPatternPos(string, string);

string giveStringAfterPattern(string str, string pattern) {
	if (str.length() > 0 && pattern.length() > 0 && str.find(pattern) == 0)
		return str.substr(str.find(pattern) + pattern.length());
	else
		return str;
}

string getHost(string url) {
	string host;
	int host_pos = url.length();

	size_t temp_pos = getPatternPos(url, ":");
	if (temp_pos != 4294967295) {
		host_pos = temp_pos;
	}
	temp_pos = getPatternPos(url, "/");
	if (temp_pos != 4294967295 && temp_pos < host_pos)
		host_pos = temp_pos;

	temp_pos = getPatternPos(url, "?");
	if (temp_pos != 4294967295 && temp_pos < host_pos)
		host_pos = temp_pos;

	host = url.substr(0, host_pos);

	return host;
}

size_t getPatternPos(std::string url, std::string pattern) {
	return url.find_first_of(pattern);
}

string getPort(string url) {
	string port_no;
	if (url.size() == 0 || url.at(0) != ':')
		port_no = "80";
	else {
		url = url.substr(1);
		int port_last_pos = url.length();

		int temp = getPatternPos(url, "/");
		if (temp != 4294967295)//found path start
			port_last_pos = temp;

		temp = getPatternPos(url, "?");
		if (temp != 4294967295 && temp < port_last_pos)//found query start
			port_last_pos = temp;

		port_no = url.substr(0, port_last_pos);
	}
	return port_no;
}

string getPath(string url) {
	string path;
	if (url.size() == 0 || url.at(0) != '/')
		path = "";
	else {
		url = url.substr(1);
		int path_pos = url.length();
		int temp = getPatternPos(url, "?");

		if (temp != 4294967295)
			path_pos = temp;
		path = url.substr(0, path_pos);
	}

	return path;
}

string getQuery(string url) {
	string query;
	if (url.size() == 0 || url.at(0) != '?')
		query = "";
	else {
		url = url.substr(1);
		query = url;
	}

	return query;
}

UrlParts UrlValidator::urlParser(string url) {
	//cout << "\t  Parsing URL... ";
	UrlParts urlParts;

	int port_no;
	string scheme, host, path, query;

	//trim
	url = url.substr(url.find_first_not_of(' '),
		(url.find_last_not_of(' ') - url.find_first_not_of(' ')) + 1);

	//removing fragment
	url = url.substr(0, url.rfind('#'));

	/*scheme part*/
	int scheme_last_pos = url.find("://");
	if (scheme_last_pos == -1) {
		scheme = "";
	}
	else {
		scheme = url.substr(0, scheme_last_pos);
		url = giveStringAfterPattern(url, scheme + "://");
	}

	//exit for incorrect scheme
	if (scheme.size() > 0 && scheme.compare("http") != 0) {
		//cout << "failed with invalid scheme" << endl;
		urlParts.isValid = -10;
		return urlParts;
	}

	host = getHost(url);
	url = giveStringAfterPattern(url, host);

	string str_port = getPort(url);

	url = giveStringAfterPattern(url, ":" + str_port);

	try {
		port_no = stoi(str_port);
		if (port_no <= 0 || port_no > 65535)
			port_no = -1;
	}
	catch (std::invalid_argument& e) {
		port_no = -1;
	}


	//exit for wrong port
	if (port_no == -1) {
		//cout << "failed with invalid port" << endl;
		urlParts.isValid = -10;
		return urlParts;
	}

	path = getPath(url);

	if (path.length() > 0)
		url = giveStringAfterPattern(url, "/" + path);

	query = getQuery(url);

	urlParts.scheme = scheme;
	urlParts.host = host;
	urlParts.port_no = port_no;
	urlParts.path = path;
	urlParts.query = query;

	/*cout << "host " << urlParts.host << ", port " << urlParts.port_no <<
		", request /" << urlParts.path << (urlParts.query.size() > 0 ? "?" : "") << urlParts.query << endl;

	/*cout << "scheme: " << urlParts.scheme << endl;
	cout << "host: " << urlParts.host << endl;
	cout << "port: " << urlParts.port_no << endl;
	cout << "path: " << urlParts.path << endl;
	cout << "query: " << urlParts.query << endl;*/

	return urlParts;
}