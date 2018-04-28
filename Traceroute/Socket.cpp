#include "Socket.h"

mutex sockDataMutex;
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

void Socket::sendICMPRequest(int ttl, sockaddr_in server) {
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
	// name in multicast headers � do not use it!
	if(setsockopt(sock, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl)))
	{
		printf("setsockopt failed with %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		exit(-1);
	}
	// use regular sendto on the above socket
	if (sendto(sock, (char*)send_buf, packet_size, 0, (SOCKADDR *)&server, sizeof(server)) == SOCKET_ERROR) {
		//return SEND_ICMP_SENDTO_SOCKERROR;
	}
	ICMPResArr[ttl] = new ICMPResponseModel();
	ICMPResArr[ttl]->packetSendTime = clock_t();
	//return SEND_ICMP_SENDTO_ALL_FINE;
}

void Socket::receiveICMPResponse(sockaddr_in server) {
	u_char rec_buf[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);
	
	//HANDLE events[] = {eventICMP, eventDNSRecv};
	int hop_count = 0;
	while (hop_count < 19) { //TODO: check when to terminate
		DWORD timeout = clock_t() + DEFAULT_TIMEOUT_DUR;

		if (WSAEventSelect(sock, eventICMP, FD_READ) == SOCKET_ERROR) {
			printf("eventICMP WSAEventSelect error %d\n", WSAGetLastError());
			exit(-1);
		}

		int ret = WaitForSingleObject(eventICMP, timeout);
		//int ret = WaitForSiObjects(1, eventICMP, FALSE, timeout);
		if (ret == WAIT_TIMEOUT)
			break;
		switch (ret) {

		case WAIT_OBJECT_0: { //ICMP event, lets receive it!
			int response_size = sizeof(server);
			int recv_res = recvfrom(sock, (char *)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL); //TODO: check if server needs to be passed
			printf("recv_res: %d\n", recv_res);
			if (recv_res == SOCKET_ERROR) {
				printf("recv failed with error %d\n", WSAGetLastError());
				exit(-1); //TODO: exit, really? Sure?
			}

			//printf("IP: %lu\n", router_ip_hdr->source_ip);
			if ((router_icmp_hdr->type == ICMP_TTL_EXPIRED || router_icmp_hdr->type == ICMP_ECHO_REPLY) && router_icmp_hdr->code == 0) { //TODO: ) bcz sendICMP had 0? and check for echo types
				if (orig_ip_hdr->proto == IPPROTO_ICMP) {
					//let's check if process id is same as current process, in short... check if packet belongs to the App! If not ignore!
					if (orig_icmp_hdr->id == GetCurrentProcessId()) {
						ICMPResArr[orig_icmp_hdr->seq]->status = true;
						ICMPResArr[orig_icmp_hdr->seq]->IP = router_ip_hdr->source_ip;
						ICMPResArr[orig_icmp_hdr->seq]->attemptCount++;
						ICMPResArr[orig_icmp_hdr->seq]->RTT = clock_t() - ICMPResArr[orig_icmp_hdr->seq]->packetSendTime;
						//take router_ip_hdr->source_ip initiaite DNS lookup
						printf("got response from IP %lu hop count %d\n", router_ip_hdr->source_ip, ++hop_count);
						
						thread dnsThread(&Socket::dnsLookUp, this, router_ip_hdr->source_ip, orig_icmp_hdr->seq);
						if (dnsThread.joinable())
							dnsThread.join();
						printf("moving on..\n");
					}
				}
			}
			WSAResetEvent(eventICMP);
		}
		break;

		case WAIT_TIMEOUT: { //handle timeout
		}
		break;
		}
	}
	printResult();
}


/*
Reference: https://stackoverflow.com/a/10564774/4135902
*/
void Socket::dnsLookUp(u_long IP, u_short seq) {
	in_addr addr;
	addr.S_un.S_addr = IP;
	char *ip_ntoa = inet_ntoa(addr);
	struct hostent *remote;
	remote = gethostbyname(ip_ntoa);
	struct addrinfo    hints;
	struct addrinfo   *res = 0;
	hints.ai_family = AF_INET;
	int status = getaddrinfo(ip_ntoa, 0, 0, &res);
	char host[512];
	status = getnameinfo(res->ai_addr, res->ai_addrlen, host, 512, 0, 0, 0);
	
	std::lock_guard<std::mutex> guard(sockDataMutex);
	ICMPResArr[seq]->char_ip = ip_ntoa;
	ICMPResArr[seq]->hostname = host;
	
	//cout << seq << "  " << ICMPResArr[seq]->char_ip << "  " << ICMPResArr[seq]->hostname << endl;
}

void Socket::printResult() {
	for (int i = 0; i < MAX_HOP; i++) {
		if (ICMPResArr[i]->char_ip.length() == 0) {
			printf("%d  *\n", i + 1);
			continue;
		}
		//cout << i + 1 << "  " << ICMPResArr[i]->hostname << "  " << ICMPResArr[i]->char_ip << endl;
		printf("%d  %s  (%s)  %0.3f ms  (%d)\n", i+1, ICMPResArr[i]->hostname.c_str(), ICMPResArr[i]->char_ip.c_str(), 
			(float)(ICMPResArr[i]->RTT)/1000, ICMPResArr[i]->attemptCount);
	}
}

void Socket::initICMPResArr() {
}

Socket::~Socket()
{
}
