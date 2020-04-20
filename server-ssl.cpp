/* ssl_server.c
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
/*** ssl_server.c                                                          ***/
/***                                                                       ***/
/*** Demonstrate an SSL server.                                            ***/
/*****************************************************************************/

#include <stdio.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <malloc.h>
#include <string.h>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#define FAIL    -1
#define PORT "1209"


WSADATA wsaData;
SOCKET ListenSocket = INVALID_SOCKET;
SOCKET ClientSocket = INVALID_SOCKET;
addrinfo* result = NULL;
addrinfo hints;

void ErrorHandling(char* message);

/*---------------------------------------------------------------------*/
/*--- OpenListener - create server socket                           ---*/
/*---------------------------------------------------------------------*/
int OpenListener(int port)
{
    struct sockaddr_in addr;

    int iResult;

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        ErrorHandling("WSAStartup() error");
    }

    memset(&addr, 0, sizeof(addr));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(NULL, PORT, &hints, &result);
    if (iResult != 0) {
        WSACleanup();
        ErrorHandling("getaddrinfo() error");
    }

    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        freeaddrinfo(result);
        WSACleanup();
        ErrorHandling("socket() error");
    }

    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        ErrorHandling("bind() error");
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        closesocket(ListenSocket);
        WSACleanup();
        ErrorHandling("listen() error");
    }
    return ListenSocket;
}

/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitServerCTX(void)
{
    SSL_METHOD* method;
    SSL_CTX* ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();        /* load & register all cryptos, etc. */
    SSL_load_error_strings();            /* load all error messages */
    method = SSLv2_server_method();        /* create new server-method instance */
    ctx = SSL_CTX_new(method);            /* create new context from method */
    if (ctx == NULL)
    {
        ErrorHandling("ctx error");
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, const char* KeyFile, const char* CertFile)
{
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ErrorHandling("SSL_CTX_use_certificate_file() error");
    }

    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ErrorHandling("SSL_CTX_use_PrivateKey_file() error");
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        ErrorHandling("SSL_CTX_check_private_key() error");
    }
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out certificates.                           ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{
    X509* cert;
    char* line;

    cert = SSL_get_peer_certificate(ssl);    /* Get certificates (if available) */
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL socket server.                              ---*/
/*---------------------------------------------------------------------*/
int main(int count, char* strings[])
{
    SSL_CTX* ctx;
    int server;
    char* portnum;

    portnum = PORT;
    ctx = InitServerCTX();                                /* initialize SSL */
    LoadCertificates(ctx, keypath.c_str(), crtpath.c_str());    /* load certs */
    server = OpenListener(atoi(portnum));                /* create server socket */

    sockaddr_in addr;
    int len = sizeof(addr);
    SSL* ssl;

    int client = accept(server, (SOCKADDR*)&addr, &len);        /* accept connection as usual */

    closesocket(ListenSocket);

    ssl = SSL_new(ctx);                             /* get new SSL state with context */
    SSL_set_fd(ssl, client);                        /* set connection socket to SSL state */

    SOCKET sClient;
    BYTE bytes;
    char buf[1024] = { 0, };

    if (SSL_accept(ssl) == FAIL)
        ErrorHandling("SSL_accept() error");
    else {
        bytes = SSL_read(ssl, buf, sizeof(buf));    /* get request */
        buf[bytes] = 0;
        printf("%s\n", buf);
        char* msg = "hello";
        printf("%s\n", msg);
        SSL_write(ssl, msg, strlen(msg));    /* send reply */
    }

    sClient = SSL_get_fd(ssl);                            /* get socket connection */
    SSL_free(ssl);                                    /* release SSL state */
    closesocket(sClient);                                        /* close connection */
    closesocket(server);                                        /* close server socket */
    SSL_CTX_free(ctx);                                    /* release context */

    DeleteFileA(keypath.c_str());
    DeleteFileA(crtpath.c_str());
}

void ErrorHandling(char* message)
{
    puts(message);
    exit(1);
}