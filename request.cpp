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
    ss<<  "GET https://sellercentral.amazon.com.br/home HTTP/1.1\r\n"
      <<"Host: sellercentral.amazon.com.br\r\n"
      <<"Connection: keep-alive\r\n"
      <<"Upgrade-Insecure-Requests: 1\r\n"
      <<"User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/70.0\r\n"
      <<"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
      << "Cookie: session-id=137-0920634-0284841; "
      << "session-id-time=2218373014l; "
      <<"ubid-acbbr=134-5474221-4905769; "
      <<"csm-hit=tb:s-EG86Y5XP7VMRNJ0C7YVP|1587653280860&t:1587653280936&adb:adblk_no; "
      <<"sst-acbbr=Sst1|PQGpv2RL-1slPBpjKVUb0X-kC4MKPhujKNOooYHExHcctecFW76ScbH7XrX5KgGMNi220ntwnJo0_hDvMdB_gQYsnnxKz6hWPO2_GErC5N0itbTbhBR0LG3booVofVs7OARxDYt6zvqo7l1GXEKdjNSsuS1bwc5DzaXONaByTFqwB4UNtjAq7eqdfK2iHEHUuX75V4ZlTASXmyU2BuVEyFm02MXINtBZcBw7M1atjuXwYquBmeIfFRdBLvPXHezJoPrpigLQfQk12mAJnjslvsYp_oFMbaQcy9P_Cu_AVrWX8Ex93CSzNNJLWYVtOuFpQk9La5pxvBZZU2HifPTWl3_sJw; "
      <<"mons-lang=en_US; "
      <<"sid=\"KvRgX9nHAJsS0Ud2X9LQew==|P+QrIVsKgrVYMO6rKXopvOLyPhonlQWborBabxvAOE8=\"; "
      <<"session-token=\"Kt69gp35KSWF2vok2enuxFsdxRuidJgURVCWrRvj3JfPIrXxHlChlsSiZijWuQx7amccyUxZLxUSUnDi1C4uulKziR729AIsfYeys6dsj99OsTNgHjrR9muilg5FEAVMHg4iaDx2FxxyBlKgLxrNROzFhvLXc9/mkOFwtAlgyedCICg+hIBL0u8pSSG+wMw7kSi0nYMTpG6LkqAotzbeSn7jaz5mm6AjVcRRmuTlYj4=\"; "
      <<"lc-acbbr=en_US; "
      <<"at-acbbr=Atza|IwEBICcBp0zphJZM9QHr7esNlkVgSm-xE8GQLeYHoho0pQoIByUQCes4l-nyFplbatD3bKRb0ymtNfbeSsclV0IYJDK1a5tskXauNcKx2EyqafUiMsc0pLxsaYgAGT59dNZjCkuolBWXvpJy1u_MKCUW_6q4pD6LtqNmIE8zpptcvWFA1T7Cc-fl4QYCJmn4ArgYv87hvJ5i-_GyICPsrjrNeVDhfLFsh-0ZH1iESI2rOHKHdu752P0OWdGGmeOmOB1iBF3zutLyB89dD_rGNN2tkPM3bf6V90bkP8UQubdPVNodMsLGb4qlLOzMlWtYzKx15llYHKxVIBkwuaCRpsex6xuj5GwAxDrrKZJUUcOrPqyLCyuVn6yWHtPgtUuOgAv73GtR405aC6FxsxBh9njbaeWvndHJvTmpSnCcY56ayp0NsQ; "
      <<"sess-at-acbbr=\"piKMO7pG+cYyUmQKOl6x62JZNFT6Ai4nc1Jq6f5RUlA=\"; "
      <<"x-acbbr=6a2pct2I4tlnaEC7FRxnTDQs5Fbp0kPVk1XtUOQ0OiyFx4y5DT3Evj2egT1V1QVE; "
      <<"__Host-mons-selections=\"H4sIAAAAAAAAAKtWSi4tLsnPTS3yTFGyUkrMrcoz1EtMTs4vzSvRy0/OTNFzDLFwjnQ38TXxMA4xVdJRAipNzkjMK0FSDxPSy8dUnViUnVpSkJOYnIqsoQCsNCzAxdvTO8LAxTVIqRYAznyr44oAAAA=\"\r\n"
      <<"Accept-Language: en-US,en;q=0.5\r\n\r\n";
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
    char data[100000];
    recvDataSSL(ssl, data, 100000l);
    return 0;
}


// connect and receive data in SSL
int connectHTTPSAMZ(SSL* ssl)
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
    char data[100000];
    recvDataSSL(ssl, data, 100000l);
    return 0;
}


