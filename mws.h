
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#define FAIL    -1



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
    union
    {
        in_addr IPv4;
        in6_addr IPv6;
        struct
        {
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
    union
    {
        in_addr IPv4;
        in6_addr IPv6;
        struct
        {
            unsigned char DomainLen;
            char Domain[256];
        };
    } BindAddr;
    unsigned short BindPort;
};


bool sendData(int soc, void* data, int len);
int recvData(int soc, void* data, int len);
int initSocketSession(int soc, char * addr, int port);

int initSslSession(int soc, SSL* &ssl,SSL_CTX *ctx);
void cleanup (int soc, SSL * ssl, SSL_CTX * ctx);
int sendDataSSL(SSL* ssl, void* data, int len);
int recvDataSSL(SSL* ssl, void* data, long len);
int recvPacket(SSL * ssl);
void log_ssl();
void showCertificate(SSL* ssl);
SSL_CTX* initSslCtx(void);


int initSocks5Session(int soc, char * addr, int port);
bool socksConnect(int soc, in_addr& dest, unsigned short port);
bool socksLogin(int soc);
bool socksRequest(int soc, const socks5_req& req, socks5_resp& resp);

int connectHTTPS(SSL* ssl);
int connectHTTP(int soc);
