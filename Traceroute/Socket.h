#pragma once
#include "common.h"
#include "CommonObj.h"
#include "utility.h"

class Socket
{
	SOCKET sock;
	HANDLE eventICMP, eventDNSRecv;
	ICMPResponseModel *ICMPResArr[MAX_HOP];
public:
	Socket();
	void initSocket();
	void sendICMPRequest(int, sockaddr_in);
	void receiveICMPResponse(sockaddr_in);
	void dnsLookUp(u_long, u_short);
	void printResult();
	void initICMPResArr();
	~Socket();
};

