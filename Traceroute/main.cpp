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

	Socket mySocket;
	mySocket.initSocket();



	WSACleanup();
	system("pause");
	return 0;
}
