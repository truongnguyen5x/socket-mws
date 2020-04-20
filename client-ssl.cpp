/* ssl_client.c
*
* Copyright (c) 2000 Sean Walton and Macmillan Publishers.  Use may be in
* whole or in part in accordance to the General Public License (GPL).
*
* THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

/*****************************************************************************/
/*** ssl_client.c                                                          ***/
/***                                                                       ***/
/*** Demonstrate an SSL client.                                            ***/
/*****************************************************************************/

#include <stdio.h>
#include <WinSock2.h>
#include <malloc.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#define FAIL    -1
#define PORT 1209
#define IPaddr "127.0.0.1"

WSADATA wsaData;
SOCKET hSocket;
SOCKADDR_IN addr;

void ErrorHandling(char* message);

/*---------------------------------------------------------------------*/
/*--- OpenConnection - create socket and connect to server.         ---*/
/*---------------------------------------------------------------------*/
int OpenConnection()
{
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        ErrorHandling("WSAStartup() error");

    hSocket = socket(PF_INET, SOCK_STREAM, 0);
    if (hSocket == INVALID_SOCKET)
        ErrorHandling("hSocket() error");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(IPaddr);
    addr.sin_port = htons(PORT);

    if (connect(hSocket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        ErrorHandling("connect() Error");
    }

    return hSocket;
}

/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitCTX(void)
{
    SSL_METHOD* method;
    SSL_CTX* ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();        /* Load cryptos, et.al. */
    SSL_load_error_strings();            /* Bring in and register error messages */
    method = SSLv2_client_method();        /* Create new client-method instance */
    ctx = SSL_CTX_new(method);            /* Create new context */
    if (ctx == NULL)
    {
        ErrorHandling("ctx Error");
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out the certificates.                       ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{
    X509* cert;
    char* line;

    cert = SSL_get_peer_certificate(ssl);    /* get the server's certificate */
    if (cert != NULL)
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

/*---------------------------------------------------------------------*/
/*--- main - create SSL context and connect                         ---*/
/*---------------------------------------------------------------------*/
int main(int count, char* strings[])
{
    SSL_CTX* ctx;
    int server;
    SSL* ssl;
    char buf[1024];
    int bytes;

    printf("press <ENTER> key\n");
    getchar();

    ctx = InitCTX();
    server = OpenConnection();
    ssl = SSL_new(ctx);                        /* create new SSL connection state */
    SSL_set_fd(ssl, server);                /* attach the socket descriptor */
    if (SSL_connect(ssl) == FAIL)            /* perform the connection */
        ErrorHandling("SSL_connect() Error");
    else
    {
        char* msg = "Hello";
        printf("%s\n", msg);
        SSL_write(ssl, msg, strlen(msg));            /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf));    /* get reply & decrypt */
        buf[bytes] = 0;
        printf("%s\n", buf);
    }

    SSL_free(ssl);                                /* release connection state */
    closesocket(server);                                    /* close socket */
    SSL_CTX_free(ctx);                                /* release context */
}

void ErrorHandling(char* message)
{
    puts(message);
    exit(1);
}
