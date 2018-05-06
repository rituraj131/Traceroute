#include "common.h"
#include "CommonObj.h"
#include "utility.h"
#include "UrlValidator.h"

void sendICMPRequest(SOCKET, int, sockaddr_in);
void receiveICMPResponse(SOCKET, sockaddr_in);
void dnsLookUp(u_long, u_short);
void printResult();
void resetRetxTimeout(long);
void retxPackets(SOCKET, sockaddr_in);
void setPacketTimeouts();
long getNeighborRTTAvg(int);

SOCKET sock;
sockaddr_in server;
ICMPResponseModel *ICMPResArr[MAX_HOP+1];
mutex dnsUpdateMutex;
thread dnsThread[MAX_HOP + 1];
clock_t retx_timeout;
DWORD exec_start;
bool exitWait = false;
LARGE_INTEGER freq;
double PCFreq;
priority_queue <HeapHopObj, vector<HeapHopObj>, TimeoutComparator> timeoutQueue;

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Usage IP/Host address required. Exiting!!\n");
		return 0;
	}

	char *host = argv[1];
	printf("Tracerouting to %s...\n", host);

	WSADATA wsaData;
	
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		cout << "WSAStartup failed with error : " << WSAGetLastError() << " Exiting!"<<endl;
		WSACleanup();
		return -1;
	}

	UrlValidator validate;
	UrlParts urlParts = validate.urlParser(host);
	char* host_char;
	if (urlParts.isValid == -10)
		host_char = host;
	else {
		host_char = new char[urlParts.host.size() + 1];
		urlParts.host.copy(host_char, urlParts.host.size());
		host_char[urlParts.host.size()] = '\0';
	}

	exec_start = timeGetTime();
	utility util;
	server = util.DNSLookUP(host_char);

	sock = util.initSocket();

	QueryPerformanceCounter(&freq);
	PCFreq = double(freq.QuadPart) / 1000.0;

	for (int i = 1; i <= 30; i++) {
		sendICMPRequest(sock, i, server);
		timeoutQueue.push(HeapHopObj(i, DEFAULT_TIMEOUT_DUR));
	}
	
	receiveICMPResponse(sock, server);

	WSACleanup();
	return 0;
}

void sendICMPRequest(SOCKET sock, int ttl, sockaddr_in server) {
	//printf("sendICMPRequest ttl %d\n", ttl);
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
	icmp->id = (u_short)GetCurrentProcessId();
	/* calculate the checksum */
	int packet_size = sizeof(ICMPHeader); // 8 bytes

	utility util;
	icmp->checksum = util.ip_checksum((u_short *)send_buf, packet_size);
	// set proper TTL
	// need Ws2tcpip.h for IP_TTL, which is equal to 4; there is another constant with the same
	// name in multicast headers – do not use it!
	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char *)&ttl, sizeof(ttl)))
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
	if(ICMPResArr[ttl] == NULL)
		ICMPResArr[ttl] = new ICMPResponseModel();
	
	//ICMPResArr[ttl]->packetSendTime = clock_t();
	QueryPerformanceCounter(&ICMPResArr[ttl]->startTime);
	ICMPResArr[ttl]->attemptCount++;
	//printf("ttl %d attemptcount %d\n", ttl, ICMPResArr[ttl]->attemptCount);
	//return SEND_ICMP_SENDTO_ALL_FINE;
}


/*
queryperformancecounter
Ref: https://stackoverflow.com/a/1739265/4135902
https://www.youtube.com/watch?v=SodHvciZTNk
https://msdn.microsoft.com/en-us/library/windows/desktop/dn553408(v=vs.85).aspx
*/
void receiveICMPResponse(SOCKET sock, sockaddr_in server) {
	u_char rec_buf[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);
	HANDLE eventICMP = WSACreateEvent();

	bool isExit = false;
	resetRetxTimeout(DEFAULT_TIMEOUT_DUR);

	while (!exitWait) { //TODO: check when to terminate
		clock_t timeout = retx_timeout - clock_t();

		if (WSAEventSelect(sock, eventICMP, FD_READ) == SOCKET_ERROR) {
			printf("eventICMP WSAEventSelect error %d\n", WSAGetLastError());
			exit(-1);
		}

		int ret = WaitForSingleObject(eventICMP, timeout);
		switch (ret) {

		case WAIT_OBJECT_0: { //ICMP event, lets receive it!
			int response_size = sizeof(server);
			int recv_res = recvfrom(sock, (char *)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL); //TODO: check if server needs to be passed
			//printf("recv_res: %d\n", recv_res);
			if (recv_res == SOCKET_ERROR) {
				printf("recv failed with error %d\n", WSAGetLastError());
				exit(-1); //TODO: exit, really? Sure?
			}
			
			if ((router_icmp_hdr->type == ICMP_TTL_EXPIRED || router_icmp_hdr->type == ICMP_ECHO_REPLY) && router_icmp_hdr->code == 0) { //TODO: ) bcz sendICMP had 0? and check for echo types
				if (orig_ip_hdr->proto == IPPROTO_ICMP) {

					ICMPHeader *icmpHeader;
					if (router_icmp_hdr->type == ICMP_ECHO_REPLY)
						icmpHeader = router_icmp_hdr;
					else
						icmpHeader = orig_icmp_hdr;
					
					if (icmpHeader->id == GetCurrentProcessId() && !ICMPResArr[icmpHeader->seq]->gotResponse) {
						ICMPResArr[icmpHeader->seq]->IP = router_ip_hdr->source_ip;
						ICMPResArr[icmpHeader->seq]->gotResponse = true;
						LARGE_INTEGER endTime;
						QueryPerformanceCounter(&endTime);
						//printf("%f\n", (endTime.QuadPart - ICMPResArr[icmpHeader->seq]->startTime.QuadPart)/PCFreq);
						ICMPResArr[icmpHeader->seq]->RTT = 1e3 * double((endTime.QuadPart - ICMPResArr[icmpHeader->seq]->startTime.QuadPart) / PCFreq);

						dnsThread[icmpHeader->seq] = thread(dnsLookUp, router_ip_hdr->source_ip, icmpHeader->seq);

						if (router_icmp_hdr->type == ICMP_ECHO_REPLY) {
							//exitWait = true;
							ICMPResArr[icmpHeader->seq]->isEcho = true;
							ICMPResArr[icmpHeader->seq]->isLast = true;
						}
					}
				}
			}
			WSAResetEvent(eventICMP);
		}
		break;

		case WAIT_TIMEOUT: { //handle timeout
			setPacketTimeouts();
		}
		break;
		}
	}

	for (int i = 1; i <= MAX_HOP; i++) {
		if (dnsThread[i].joinable())
			dnsThread[i].join();
	}
	printResult();
}

/*
Reference: https://stackoverflow.com/a/10564774/4135902
http://en.cppreference.com/w/cpp/thread/mutex
*/
void dnsLookUp(u_long IP, u_short seq) {
	in_addr addr;
	addr.S_un.S_addr = IP;
	char *ip_ntoa = inet_ntoa(addr);
	/*struct hostent *remote;
	remote = gethostbyname(ip_ntoa);*/
	struct addrinfo    hints;
	struct addrinfo   *res = 0;
	hints.ai_family = AF_INET;
	int status = getaddrinfo(ip_ntoa, 0, 0, &res);
	char host[512];
	status = getnameinfo(res->ai_addr, res->ai_addrlen, host, 512, 0, 0, 0);
	string str_ip_ntoa(ip_ntoa);
	string str_host(host);
	
	std::lock_guard<std::mutex> guard(dnsUpdateMutex);
	if (str_ip_ntoa.compare(str_host) == 0)
		ICMPResArr[seq]->hostname = "<no DNS entry>";
	else
		ICMPResArr[seq]->hostname = host;

	ICMPResArr[seq]->char_ip = ip_ntoa;
	/*printf("%d  %s  (%s)  %d ms  (%f) %d\n", seq, ICMPResArr[seq]->hostname.c_str(), ICMPResArr[seq]->char_ip.c_str(),
		ICMPResArr[seq]->RTT, ICMPResArr[seq]->attemptCount);*/
}

void printResult() {
	//printf("\nprinting results\n");
	for (int i = 1; i <= MAX_HOP; i++) {
		if (ICMPResArr[i]->char_ip.length() == 0) {
			printf("%d  *\n", i);
			continue;
		}
		printf("%d  %s  (%s)  %0.3f ms  (%d)\n", i, ICMPResArr[i]->hostname.c_str(), ICMPResArr[i]->char_ip.c_str(),
			ICMPResArr[i]->RTT, ICMPResArr[i]->attemptCount);
		if (ICMPResArr[i]->isEcho)
			break;
	}

	printf("\nTotal execution time %d ms\n\n", timeGetTime() - exec_start);
}

void resetRetxTimeout(long timeout) {
	retx_timeout = clock_t() + timeout;
}

void retxPackets(SOCKET sock, sockaddr_in server) {
	bool isAnyRetx = false;
	//printf("retxPackets...\n");
	for (int i = 1; i <= MAX_HOP; i++) {
		if (!ICMPResArr[i]->gotResponse && ICMPResArr[i]->attemptCount < 3) {
			//printf(" %d %d    ", i, ICMPResArr[i]->attemptCount);
			sendICMPRequest(sock, i, server);
			isAnyRetx = true;
		}
	}

	if (!isAnyRetx)
		exitWait = true;
}

void setPacketTimeouts() {
	if (timeoutQueue.size() == 0) {
		exitWait = true;
		return;
	}
	//printf("setPacketTimeouts\n");
	vector<int> listRetxSeq;

	//we know there has been a timeout, the top entry on min heap is surely exprired, lets take it out.
	HeapHopObj heapObj = timeoutQueue.top();
	timeoutQueue.pop();
	while (ICMPResArr[heapObj.ttl]->gotResponse || ICMPResArr[heapObj.ttl]->attemptCount >= 3) {
		if (timeoutQueue.size() == 0) {
			exitWait = true;
			return;
		}

		heapObj = timeoutQueue.top();
		timeoutQueue.pop();
	}

	listRetxSeq.push_back(heapObj.ttl);
	long ref_timeout = heapObj.timeout;

	while (timeoutQueue.size() > 0) {
		//if next one has also expired, tke it out first!
		if (timeoutQueue.top().timeout <= ref_timeout) {
			heapObj = timeoutQueue.top();
			//the this one has not been received lets take it for retx.
			if(!ICMPResArr[heapObj.ttl]->gotResponse && ICMPResArr[heapObj.ttl]->attemptCount < 3)
				listRetxSeq.push_back(heapObj.ttl);
		}
		else
			break;
		timeoutQueue.pop();
	}
	long minFinalRTT = LONG_MAX;
	int currPQSize = timeoutQueue.size();
	for (int i = 0; i < currPQSize; i++) {
		HeapHopObj heapHopObj = timeoutQueue.top();
		timeoutQueue.pop();
		heapHopObj.timeout = heapHopObj.timeout - ref_timeout;
		timeoutQueue.push(heapHopObj);
		//minFinalRTT = min(minFinalRTT, heapHopObj.timeout);
	}
	
	//timeoutQueue = priority_queue <HeapHopObj, vector<HeapHopObj>, TimeoutComparator>(); //reset
	
	bool isAnyRetx = false;
	
	for (int i = 0; i < listRetxSeq.size(); i++) {
		long neighborAvg = getNeighborRTTAvg(listRetxSeq.at(i));
		long calc_RTT;
		if (neighborAvg > 0)
			calc_RTT = EXTRA_BUFFER_TIMEOUT + ceil(ALPHA * (float)MAP_AVG_HOP_RTT[listRetxSeq.at(i)] + (1 - ALPHA) * (float)neighborAvg);
		else
			calc_RTT = MAP_AVG_HOP_RTT[listRetxSeq.at(i)] + EXTRA_BUFFER_TIMEOUT;

		long timeout = max(MINIMUM_BUFFER_TIMEOUT, calc_RTT);
		//printf("seq %d timeout %d calc_RTT %d\n", listRetxSeq.at(i), timeout, calc_RTT);
		minFinalRTT = min(minFinalRTT, timeout);
		sendICMPRequest(sock, listRetxSeq.at(i), server);
		timeoutQueue.push(HeapHopObj(listRetxSeq.at(i), timeout));
		isAnyRetx = true;
	}

	if(minFinalRTT < LONG_MAX)
		resetRetxTimeout(minFinalRTT);

	if (!isAnyRetx) {
		exitWait = true;
		//printf("please exit now\n");
	}
}

long getNeighborRTTAvg(int ttl) {
	long avg = 0;
	if (ttl > 1 && ICMPResArr[ttl - 1]->gotResponse)
		avg = ceil(ICMPResArr[ttl - 1]->RTT);
	if (ttl < 30 && ICMPResArr[ttl + 1]->gotResponse) {
		if (avg > 0) {//we got something from ttl-1., lets avg both of them now.
			avg += ceil(ICMPResArr[ttl + 1]->RTT);
			avg = ceil((float)avg / 2);
		}
		else
			avg = ceil(ICMPResArr[ttl + 1]->RTT);
	}

	return avg;
}