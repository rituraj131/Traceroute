#pragma once
class utility
{
public:
	u_short ip_checksum(u_short *buffer, int size);
	struct sockaddr_in DNSLookUP(char*);
	SOCKET initSocket();
};

