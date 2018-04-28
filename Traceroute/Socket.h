#pragma once
#include "common.h"
#include "CommonObj.h"
#include "utility.h"

class Socket
{
	SOCKET sock;
	HANDLE eventICMP, eventDNSRecv;
public:
	Socket();
	void initSocket();
	int sendICMPRequest(int, sockaddr_in);
	void receiveICMPResponse(sockaddr_in);
	~Socket();
};

