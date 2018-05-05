#include "common.h"
#include "utility.h"

u_short utility::ip_checksum(u_short *buffer, int size)
{
	u_long cksum = 0;

	/* sum all the words together, adding the final byte if size is odd */
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(u_short);
	}

	if (size)
		cksum += *(u_char *)buffer;

	/* add carry bits to lower u_short word */
	cksum = (cksum >> 16) + (cksum & 0xffff);

	/* return a bitwise complement of the resulting mishmash */
	return (u_short)(~cksum);
}

struct sockaddr_in utility::DNSLookUP(char* host) {
	struct sockaddr_in server;
	char *address;
	struct hostent *remote;
	in_addr addr;
	DWORD IP = inet_addr(host);

	if (IP == INADDR_NONE)
	{
		// if not a valid IP, then do a DNS lookup
		if ((remote = gethostbyname(host)) == NULL)
		{
			//cout << "DNS lookup for host name failed with error " << WSAGetLastError() << endl;
			return server;
			//exit(-1);
		}
		else // take the first IP address and copy into sin_addr
		{
			memcpy((char *)&(server.sin_addr), remote->h_addr, remote->h_length);
			addr.s_addr = *(u_long *)remote->h_addr;
			address = inet_ntoa(addr);
		}
	}
	else
	{
		// if a valid IP, directly drop its binary version into sin_addr
		server.sin_addr.S_un.S_addr = IP;
		address = host;
	}

	// setup the port # and protocol type
	server.sin_family = AF_INET;
	server.sin_port = htons(80); //But why 80? may be since there are no port numbers in ICMP!?

	return server;
}

SOCKET utility::initSocket() {
	/* ready to create a socket */
	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}

	return sock;
}