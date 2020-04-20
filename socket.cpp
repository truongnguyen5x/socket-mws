#include <stdio.h>
#include <winsock.h>
#include <stdlib.h>
#pragma comment(lib,"ws2_32.lib")
#include <in6addr.h>


struct socks5_ident_req
{
	unsigned char Version;
	unsigned char NumberOfMethods;
	unsigned char Methods[256];
};

struct socks5_ident_resp
{
	unsigned char Version;
	unsigned char Method;
};

struct socks5_req
{
	unsigned char Version;
	unsigned char Cmd;
	unsigned char Reserved;
	unsigned char AddrType;
	union {
		in_addr IPv4;
		in6_addr IPv6;
		struct {
			unsigned char DomainLen;
			char Domain[256];
		};
	} DestAddr;
	unsigned short DestPort;
};

struct socks5_resp
{
	unsigned char Version;
	unsigned char Reply;
	unsigned char Reserved;
	unsigned char AddrType;
	union {
		in_addr IPv4;
		in6_addr IPv6;
		struct {
			unsigned char DomainLen;
			char Domain[256];
		};
	} BindAddr;
	unsigned short BindPort;
};


bool sendData(SOCKET fd, void* data, int len)
{
	char* ptr = (char*)data;

	while (len > 0)
	{
		int sent = send(fd, ptr, len, 0);
		if (sent <= 0)
		{
			printf("send() error: %d", WSAGetLastError());
			return false;
		}
		ptr += sent;
		len -= sent;
	}

	return true;
}

int recvData(SOCKET fd, void* data, int len, bool disconnectOk = false)
{
	char* ptr = (char*)data;
	int total = 0;

	while (len > 0)
	{
		int recvd = recv(fd, ptr, len, 0);
		if (recvd < 0)
		{
			printf("recv() error: %d", WSAGetLastError());
			return -1;
		}
		if (recvd == 0)
		{
			if (disconnectOk)
				break;
			printf("disconnected");
			return -1;
		}
		ptr += recvd;
		len -= recvd;
		total -= recvd;
	}

	return total;
}

bool socksLogin(SOCKET fd)
{
	socks5_ident_req req;
	socks5_ident_resp resp;

	req.Version = 5;
	req.NumberOfMethods = 1;
	req.Methods[0] = 0x00;
	// add other methods as needed...

	if (!sendData(fd, &req, 2 + req.NumberOfMethods))
		return false;

	if (recvData(fd, &resp, sizeof(resp)) == -1)
		return false;

	if (resp.Version != 5)
	{
		printf("SOCKS v5 identification failed");
		return false;
	}

	if (resp.Method == 0xFF)
	{
		printf("SOCKS v5 authentication failed");
		return false;
	}

	/*
	if (resp.Method != 0x00)
	{
		// authenticate as needed...
	}
	*/

	return true;
}

bool socksRequest(SOCKET fd, const socks5_req& req, socks5_resp& resp)
{
	memset(&resp, 0, sizeof(resp));

	if (!sendData(fd, (void*)&req, 4))
		return false;

	switch (req.AddrType)
	{
	case 1:
	{
		if (!sendData(fd, (void*)&(req.DestAddr.IPv4), sizeof(in_addr)))
			return false;

		break;
	}
	case 3:
	{
		if (!sendData(fd, (void*)&(req.DestAddr.DomainLen), 1))
			return false;

		if (!sendData(fd, (void*)req.DestAddr.Domain, req.DestAddr.DomainLen))
			return false;

		break;
	}
	case 4:
	{
		if (!sendData(fd, (void*)&(req.DestAddr.IPv6), sizeof(in6_addr)))
			return false;

		break;
	}

	default:
	{
		printf("SOCKS 5 requesting unknown address type");
		return false;
	}
	}

	unsigned short port = htons(req.DestPort);
	if (!sendData(fd, &port, 2))
		return false;

	if (recvData(fd, &resp, 4) == -1)
		return false;

	switch (resp.AddrType)
	{
	case 1:
	{
		if (recvData(fd, &(resp.BindAddr.IPv4), sizeof(in_addr)) == -1)
			return false;

		break;
	}
	case 3:
	{
		if (recvData(fd, &(resp.BindAddr.DomainLen), 1) == -1)
			return false;

		if (recvData(fd, resp.BindAddr.Domain, resp.BindAddr.DomainLen) == -1)
			return false;

		break;
	}
	case 4:
	{
		if (recvData(fd, &(resp.BindAddr.IPv6), sizeof(in6_addr)) == -1)
			return false;

		break;
	}

	default:
	{
		printf("SOCKS 5 bound to unknown address type");
		return false;
	}
	}

	if (recvData(fd, &port, 2, 0) == -1)
		return false;

	resp.BindPort = ntohs(port);

	return true;
}

bool socksConnect(SOCKET fd, in_addr& dest, unsigned short port)
{
	socks5_req req;
	socks5_resp resp;

	req.Version = 5;
	req.Cmd = 1;
	req.Reserved = 0;
	req.AddrType = 1;
	req.DestAddr.IPv4 = dest;
	req.DestPort = port;

	if (!socksRequest(fd, req, resp))
		return false;

	if (resp.Reply != 0x00)
	{
		printf("SOCKS v5 connect failed, error: 0x%02X", resp.Reply);
		return false;
	}
	else {
		printf("Socks v5 establised ");
	}

	return true;
}

int main()
{
	WSADATA wsa;
	SOCKET s;
	struct sockaddr_in server;
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		return 1;
	}
	printf("Initialised.\n");

	//Create a socket
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d", WSAGetLastError());
	}

	printf("Socket created.\n");

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(5001);

	//Connect to remote server
	if (connect(s, (struct sockaddr*) & server, sizeof(server)) < 0)
	{
		puts("connect error");
		return 1;
	}
	if (!socksLogin(s)) {
		return 1;
	}
	else {
		puts("done");
	}

	struct in_addr paddr;
	DWORD ip = inet_addr("35.240.177.81");
	paddr.S_un.S_addr = ip;
	if (!socksConnect(s, paddr, 80))
		return 1;

	printf("Success! Suceess");

	char* query = "GET http://35.240.177.81/ HTTP/1.1\r\nHost: 35.240.177.81\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n";
		
	if (!sendData(s, query, strlen(query))) {
		return 0;
	}
	char result[4000];
	if (!recvData(s, result, 4000)) {
		return 0;
	}
	else {
		puts(result);
	}

	// now send/receive desired data as needed using existing fd ...

	return 0;
}