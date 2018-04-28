#pragma once
#include "common.h"
#include "CommonObj.h"
#include "utility.h"

class Socket
{
	SOCKET sock;
	HANDLE eventICMP, eventDNSRecv;
	ICMPResponseModel *ICMPResArr[MAX_HOP+1];
public:
	Socket();
	void initSocket();
	void sendICMPRequest(int, sockaddr_in);
	void receiveICMPResponse(sockaddr_in);
	~Socket();
};

