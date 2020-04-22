#include "mws.h"

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

int initSocks5Session(int soc, char * addr, int port)
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

int initSslSession(int soc, SSL* &ssl,SSL_CTX *ctx)
{
    ctx = initSslCtx();
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
        showCertificate(ssl);
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
