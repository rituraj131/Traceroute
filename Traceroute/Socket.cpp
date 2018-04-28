#include "Socket.h"

Socket::Socket()
{
	eventICMP = WSACreateEvent();
	eventDNSRecv = WSACreateEvent();
}

void Socket::initSocket() {
	/* ready to create a socket */
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}
}

int Socket::sendICMPRequest(int ttl, sockaddr_in server) {
	// buffer for the ICMP header
	u_char send_buf[MAX_ICMP_SIZE]; /* IP header is not present here */
	ICMPHeader *icmp = (ICMPHeader *)send_buf;

	// set up the echo request
	// no need to flip the byte order
	icmp->type = ICMP_ECHO_REQUEST;
	icmp->code = 0;
	// set up ID/SEQ fields as needed
	icmp->seq = ttl;
	icmp->checksum = 0;
	icmp->id = (u_short) GetCurrentProcessId();
	/* calculate the checksum */
	int packet_size = sizeof(ICMPHeader); // 8 bytes
	
	utility util;
	icmp->checksum = util.ip_checksum((u_short *)send_buf, packet_size);
	// set proper TTL
	// need Ws2tcpip.h for IP_TTL, which is equal to 4; there is another constant with the same
	// name in multicast headers – do not use it!
	if(setsockopt(sock, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl)))
	{
		printf("setsockopt failed with %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		exit(-1);
	}
	// use regular sendto on the above socket
	if (sendto(sock, (char*)send_buf, packet_size, 0, (SOCKADDR *)&server, sizeof(server)) == SOCKET_ERROR) {
		return SEND_ICMP_SENDTO_SOCKERROR;
	}

	//TODO: do something man!

	return SEND_ICMP_SENDTO_ALL_FINE;
}

void Socket::receiveICMPResponse(sockaddr_in server) {
	u_char rec_buf[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);
	
	WSAEventSelect(sock, eventICMP, FD_READ);
	WSAEventSelect(sock, eventDNSRecv, FD_READ);
	HANDLE events[] = {eventICMP, eventDNSRecv};

	while (true) { //TODO: check when to terminate
		DWORD timeout;
		int ret = WaitForMultipleObjects(2, events, FALSE, timeout);

		switch (ret) {

		case WAIT_OBJECT_0://ICMP event
			break;

		case WAIT_OBJECT_0 +1://DNS event
			break;

		default://handle timeout
		}
	}
}

Socket::~Socket()
{
}
