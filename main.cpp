#include "mws.h"

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
    if (!initSocketSession(soc, socks5ip, 27540))
    {
        return FAIL;
    }
    char address[] = "172.217.5.238";
    if (!initSocks5Session(soc, address, 443))
    {
        return FAIL;
    }
    if (!initSslSession(soc, ssl, ctx))
    {
        return FAIL;
    }
    connectHTTPS(ssl);
    cleanup(soc, ssl, ctx);
    return 0;
}
