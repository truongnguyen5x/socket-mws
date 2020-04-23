#include "mws.h"


// send data to socket with length
bool sendData(int soc, void* data, int len)
{
    char* ptr = (char*)data;

    while (len > 0)
    {
        int sent = send(soc, ptr, len, 0);
        if (sent <= 0)
        {
            printf("send socket error");
            return false;
        }
        ptr += sent;
        len -= sent;
    }

    return true;
}



// receive data from socket
int recvData(int soc, void* data, int len)
{
    char* ptr = (char*)data;
    int total = 0;

    while (len > 0)
    {
        int recvd = recv(soc, ptr, len, 0);
        if (recvd < 0)
        {
            printf("recv socket error");
            return FAIL;
        }
        ptr += recvd;
        len -= recvd;
        total += recvd;
    }

    return total;
}

int initSocketSession(int soc, char * addr, int port)
{
    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(addr);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (connect(soc, (struct sockaddr*) & server, sizeof(server)) < 0)
    {
        return FAIL;
    }
    return 1;
}





