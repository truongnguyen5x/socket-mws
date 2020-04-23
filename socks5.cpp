#include "mws.h"



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
