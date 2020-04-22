#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
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


// send data wrap with SSL
bool sendDataSSL(SSL* ssl, void* data, int len)
{
    char* ptr = (char*)data;

    while (len > 0)
    {
        int sent = SSL_write(ssl, ptr, len);
        if (sent <= 0)
        {
            printf("send ssl/tls error");
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


int recvDataSSL(SSL* ssl, void* data, int len)
{
    char* ptr = (char*)data;
    int total = 0;

    while (len > 0)
    {
        int recvd = SSL_read(ssl, ptr, len);
        if (recvd < 0)
        {
            printf("recv ssl/tls error");
            return FAIL;
        }
        ptr += recvd;
        len -= recvd;
        total += recvd;
    }

    return total;
}


bool socksLogin(int soc)
{
    socks5_ident_req req;
    socks5_ident_resp resp;

    req.Version = 5;
    req.NumberOfMethods = 1;
    req.Methods[0] = 0x00;
    // add other methods as needed...

    if (!sendData(soc, &req, 2 + req.NumberOfMethods))
        return false;

    if (recvData(soc, &resp, sizeof(resp)) == -1)
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
    return true;
}

// ask socks5 server to connect other ip
bool socksRequest(int soc, const socks5_req& req, socks5_resp& resp)
{
    if (!sendData(soc, (void*)&req, 4))
        return false;

    switch (req.AddrType)
    {
    case 1:
    {
        if (!sendData(soc, (void*)&(req.DestAddr.IPv4), sizeof(in_addr)))
            return false;

        break;
    }
    case 3:
    {
        if (!sendData(soc, (void*)&(req.DestAddr.DomainLen), 1))
            return false;

        if (!sendData(soc, (void*)req.DestAddr.Domain, req.DestAddr.DomainLen))
            return false;

        break;
    }
    case 4:
    {
        if (!sendData(soc, (void*)&(req.DestAddr.IPv6), sizeof(in6_addr)))
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
    if (!sendData(soc, &port, 2))
        return false;

    if (recvData(soc, &resp, 4) == -1)
        return false;

    switch (resp.AddrType)
    {
    case 1:
    {
        if (recvData(soc, &(resp.BindAddr.IPv4), sizeof(in_addr)) == -1)
            return false;

        break;
    }
    case 3:
    {
        if (recvData(soc, &(resp.BindAddr.DomainLen), 1) == -1)
            return false;

        if (recvData(soc, resp.BindAddr.Domain, resp.BindAddr.DomainLen) == -1)
            return false;

        break;
    }
    case 4:
    {
        if (recvData(soc, &(resp.BindAddr.IPv6), sizeof(in6_addr)) == -1)
            return false;

        break;
    }

    default:
    {
        printf("SOCKS 5 bound to unknown address type");
        return false;
    }
    }

    if (recvData(soc, &port, 2) == -1)
        return false;

    resp.BindPort = ntohs(port);

    return true;
}

// send hello to socks5 server
bool socksConnect(int soc, in_addr& dest, unsigned short port)
{
    socks5_req req;
    socks5_resp resp;

    req.Version = 5;
    req.Cmd = 1;
    req.Reserved = 0;
    req.AddrType = 1;
    req.DestAddr.IPv4 = dest;
    req.DestPort = port;

    if (!socksRequest(soc, req, resp))
        return false;

    if (resp.Reply != 0x00)
    {
        printf("SOCKS v5 connect failed, error: 0x%02X", resp.Reply);
        return false;
    }
    return true;
}
/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitCTX(void)
{

    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out the certificates.                       ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);    /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);                            /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);                            /* free the malloc'ed string */
        X509_free(cert);                    /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

// connect and receive data in http
int connectHttp(int soc)
{
    std::stringstream ss;
    ss<< "GET http://35.240.177.81/ HTTP/1.1\r\nHost: 35.240.177.81\r\n"
      << "Connection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n"
      << "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36\r\n"
      << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
      << "Accept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n";
    std::string str = ss.str();
    char * query = new char[str.length()];
    strcpy(query, str.c_str());
    if (!sendData(soc, query, strlen(query)))
    {
        return 0;
    }
    char result[4000];
    if (!recvData(soc, result, 4000))
    {
        return 0;
    }
    else
    {
        puts("\n");
        puts(result);
    }
    return 0;
}

// connect and receive data in SSL
int connectHTTPS(SSL* ssl)
{
    std::stringstream ss;
    ss<<  "GET https://www.google.com/?gws_rd=ssl HTTP/1.1\r\n"
      <<"Host: www.google.com\r\n"
      <<"Connection: keep-alive\r\n"
      <<"Upgrade-Insecure-Requests: 1\r\n"
      <<"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36\r\n"
      <<"Sec-Fetch-Site: none\r\n"
      <<"Sec-Fetch-Mode: navigate\r\n"
      <<"Sec-Fetch-User: ?1\r\n"
      <<"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
      <<"Accept-Encoding: gzip, deflate\r\n"
      <<"Accept-Language: en-US,en;q=0.9\r\n\r\n";
    std::string str = ss.str();
    char * query = new char[str.length()];
    strcpy(query, str.c_str());
    if (!sendDataSSL(ssl, query, strlen(query)))
    {
        return 0;
    }
    char result[56000];
    if (!recvDataSSL(ssl, result, 56000))
    {
        return 0;
    }
    else
    {
        puts("\n");
        puts(result);
    }
    return 0;
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

int socks5Session(int soc, char * addr, int port)
{
    if (!socksLogin(soc))
    {
        return FAIL;
    }
    struct sockaddr_in sa;
    inet_pton(AF_INET, addr, &(sa.sin_addr));
    if (!socksConnect(soc, sa.sin_addr, port))
        return FAIL;
    return 1;
}

int initSSLSession(int soc, SSL* &ssl,SSL_CTX *ctx)
{
    ctx = InitCTX();
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, soc);
    if ( SSL_connect(ssl) == FAIL )
    {
        ERR_print_errors_fp(stderr);
        return FAIL;
    }
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
        return 1;
    }
}


void cleanup (int soc, SSL * ssl, SSL_CTX * ctx)
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(soc);
    SSL_CTX_free(ctx);
    EVP_cleanup();
}


int main()
{
    int soc;
    SSL *ssl;
    SSL_CTX *ctx;
    if ((soc = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return FAIL;
    }
    char socks5ip[] = "192.168.3.5";
    if (!initSocketSession(soc, socks5ip, 34974))
    {
        return FAIL;
    }
    char address[] = "172.217.5.238";
    if (!socks5Session(soc, address, 443))
    {
        return FAIL;
    }
    if (!initSSLSession(soc, ssl, ctx))
    {
        return FAIL;
    }
    connectHTTPS(ssl);
    cleanup(soc, ssl, ctx);
    return 0;
}



