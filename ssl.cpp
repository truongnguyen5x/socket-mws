#include "mws.h"


// send data wrap with SSL
int sendDataSSL(SSL* ssl, void* data, int len)
{
    char* ptr = (char*)data;
    while (len > 0)
    {
        int sent = SSL_write(ssl, ptr, len);
        if (sent <0)
        {
            int err = SSL_get_error(ssl, sent);
            switch (err)
            {
            case SSL_ERROR_WANT_WRITE:
                printf("SSL_ERROR_WANT_WRITE");
                return 0;
            case SSL_ERROR_WANT_READ:
                printf("SSL_ERROR_WANT_READ");
                return 0;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            default:
                return FAIL;
            }
        }
        ptr += sent;
        len -= sent;
    }
    return 1;
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



void log_ssl()
{
    int err;
    while (err = ERR_get_error())
    {
        char *str = ERR_error_string(err, 0);
        if (!str)
            return;
        printf(str);
        printf("\n");
        fflush(stdout);
    }
}






/*---------------------------------------------------------------------*/
/*--- initSslCtx - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* initSslCtx(void)
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
/*--- showCertificate - print out the certificates.                       ---*/
/*---------------------------------------------------------------------*/
void showCertificate(SSL* ssl)
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


int recvPacket(SSL * ssl)
{
    int len=100;
    char buf[1000000];
    do
    {
        len=SSL_read(ssl, buf, 100);
        buf[len]=0;
        printf(buf);
    }
    while (len > 0);
    if (len < 0)
    {
        int err = SSL_get_error(ssl, len);
        if (err == SSL_ERROR_WANT_READ)
            return 0;
        if (err == SSL_ERROR_WANT_WRITE)
            return 0;
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
            return FAIL;
    }
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


