#include "mws.h"



// connect and receive data in http
int connectHTTP(int soc)
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
    std::cout<<"\n Request send: \n" << query << std::endl;
    if (!sendDataSSL(ssl, query, strlen(query)))
    {
        log_ssl();
        return 0;
    }
    std::cout<<"\n Request receive: \n" << std::endl;
    recvPacket(ssl);
    return 0;
}

