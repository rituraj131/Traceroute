#include "common.h"
#include "Socket.h"

int main(int argc, char **argv) {
	if (argc != 2) {
		printf("Usage IP/Host address required. Exiting!!\n");
		return 0;
	}

	char *host = argv[1];
	printf("host %s\n", host);

	WSADATA wsaData;
	
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		cout << "WSAStartup failed with error : " << WSAGetLastError() << " Exiting!"<<endl;
		WSACleanup();
		return -1;
	}

	utility util;
	struct sockaddr_in server = util.DNSLookUP(host);

	Socket mySocket;
	mySocket.initSocket();

	for (int i = 1; i <= 30; i++) {
		//TODO: check what and how to do 3 probes per hop!
		mySocket.sendICMPRequest(i, server);
	}

	WSACleanup();
	system("pause");
	return 0;
}
