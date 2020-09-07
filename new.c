#include<stdio.h>
#include<winsock2.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS


#pragma comment(lib,"ws2_32")
int main(int argc , char *argv[]){
	WSADATA wsaData;
    struct sockaddr_in hax;
	SOCKET s1;
	PROCESS_INFORMATION pi;
	STARTUPINFO sui;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	s1 = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL,
		(unsigned int)NULL, (unsigned int)NULL);
	printf("%d\n", WSAGetLastError());
	hax.sin_family = AF_INET;
	hax.sin_port = htons(4444);
	hax.sin_addr.s_addr = inet_addr("192.168.2.130");
	//sui = 68 decimal 
	printf("%d", sizeof(pi));	
	return 0;
}
