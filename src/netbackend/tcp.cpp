// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include "config/dash-config.h"
#endif

#include <string>
#include <stdexcept>
#include <algorithm>

#ifndef WIN32
#include <fcntl.h>
#endif

#if !defined(HAVE_MSG_NOSIGNAL) && !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#include "util.h"
#include "chainparams.h"
#include "utilstrencodings.h"
#include "netbase.h"
#include "netbackend/tcp.h"

static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
static const unsigned char pchOnionCat[] = {0xFD,0x87,0xD8,0x7E,0xEB,0x43};

static bool IsTor(const CNetAddr& addr)
{
    return (memcmp(addr.GetRaw(), pchOnionCat, sizeof(pchOnionCat)) == 0);
}

// IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
static bool IsIPv4(const CNetAddr& addr)
{
    return (memcmp(addr.GetRaw(), pchIPv4, sizeof(pchIPv4)) == 0);
}

// IPv6 address (not mapped IPv4, not Tor)
static bool IsIPv6(const CNetAddr& addr)
{
    return (!IsIPv4(addr) && !IsTor(addr));
}

// IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
static bool IsRFC1918(const CNetAddr& addr)
{
    return IsIPv4(addr) && (
        addr.GetByte(3) == 10 ||
        (addr.GetByte(3) == 192 && addr.GetByte(2) == 168) ||
        (addr.GetByte(3) == 172 && (addr.GetByte(2) >= 16 && addr.GetByte(2) <= 31)));
}

// IPv4 inter-network communications (192.18.0.0/15)
static bool IsRFC2544(const CNetAddr& addr)
{
    return IsIPv4(addr) && addr.GetByte(3) == 198 &&
           (addr.GetByte(2) == 18 || addr.GetByte(2) == 19);
}

// IPv4 autoconfig (169.254.0.0/16)
static bool IsRFC3927(const CNetAddr& addr)
{
    return IsIPv4(addr) && (addr.GetByte(3) == 169 && addr.GetByte(2) == 254);
}

// IPv4 ISP-level NAT (100.64.0.0/10)
static bool IsRFC6598(const CNetAddr& addr)
{
    return IsIPv4(addr) && addr.GetByte(3) == 100 &&
           addr.GetByte(2) >= 64 && addr.GetByte(2) <= 127;
}

// IPv4 documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
static bool IsRFC5737(const CNetAddr& addr)
{
    return IsIPv4(addr) &&
           ((addr.GetByte(3) == 192 &&
             addr.GetByte(2) == 0 &&
             addr.GetByte(1) == 2) ||
            (addr.GetByte(3) == 198 &&
             addr.GetByte(2) == 51 &&
             addr.GetByte(1) == 100) ||
            (addr.GetByte(3) == 203 &&
             addr.GetByte(2) == 0 &&
             addr.GetByte(1) == 113));
}

// IPv6 documentation address (2001:0DB8::/32)
static bool IsRFC3849(const CNetAddr& addr)
{
    return addr.GetByte(15) == 0x20 && addr.GetByte(14) == 0x01 &&
           addr.GetByte(13) == 0x0D && addr.GetByte(12) == 0xB8;
}

// IPv6 6to4 tunnelling (2002::/16)
static bool IsRFC3964(const CNetAddr& addr)
{
    return (addr.GetByte(15) == 0x20 && addr.GetByte(14) == 0x02);
}

// IPv6 well-known prefix (64:FF9B::/96)
static bool IsRFC6052(const CNetAddr& addr)
{
    static const unsigned char pchRFC6052[] = {0,0x64,0xFF,0x9B,0,0,0,0,0,0,0,0};
    return (memcmp(addr.GetRaw(), pchRFC6052, sizeof(pchRFC6052)) == 0);
}

// IPv6 Teredo tunnelling (2001::/32)
static bool IsRFC4380(const CNetAddr& addr)
{
    return (addr.GetByte(15) == 0x20 && addr.GetByte(14) == 0x01 &&
            addr.GetByte(13) == 0 && addr.GetByte(12) == 0);
}

// IPv6 autoconfig (FE80::/64)
static bool IsRFC4862(const CNetAddr& addr)
{
    static const unsigned char pchRFC4862[] = {0xFE,0x80,0,0,0,0,0,0};
    return (memcmp(addr.GetRaw(), pchRFC4862, sizeof(pchRFC4862)) == 0);
}

// IPv6 unique local (FC00::/7)
static bool IsRFC4193(const CNetAddr& addr)
{
    return ((addr.GetByte(15) & 0xFE) == 0xFC);
}

// IPv6 IPv4-translated address (::FFFF:0:0:0/96)
static bool IsRFC6145(const CNetAddr& addr)
{
    static const unsigned char pchRFC6145[] = {0,0,0,0,0,0,0,0,0xFF,0xFF,0,0};
    return (memcmp(addr.GetRaw(), pchRFC6145, sizeof(pchRFC6145)) == 0);
}

// IPv6 ORCHID (2001:10::/28)
static bool IsRFC4843(const CNetAddr& addr)
{
    return (addr.GetByte(15) == 0x20 && addr.GetByte(14) == 0x01 &&
            addr.GetByte(13) == 0x00 && (addr.GetByte(12) & 0xF0) == 0x10);
}

static bool GetSockAddr(const CService& addr,
                        struct sockaddr* paddr,
                        socklen_t *addrlen)
{
    if (IsIPv4(addr)) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in))
            return false;
        *addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *paddrin = (struct sockaddr_in*)paddr;
        memset(paddrin, 0, *addrlen);
        memcpy(&paddrin->sin_addr, addr.GetRaw()+12, 4);
        paddrin->sin_family = AF_INET;
        paddrin->sin_port = htons(addr.GetPort());
        return true;
    }
    if (IsIPv6(addr)) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6))
            return false;
        *addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *paddrin6 = (struct sockaddr_in6*)paddr;
        memset(paddrin6, 0, *addrlen);
        memcpy(&paddrin6->sin6_addr, addr.GetRaw(), 16);
        paddrin6->sin6_scope_id = addr.GetScopeId();
        paddrin6->sin6_family = AF_INET6;
        paddrin6->sin6_port = htons(addr.GetPort());
        return true;
    }
    return false;
}

static bool SetSockAddr(CService& addr, const struct sockaddr *paddr)
{
    switch (paddr->sa_family) {
    case AF_INET: {
        addr = CService(CNetBackendTcp::instance);
        const auto paddr4 = reinterpret_cast<const struct sockaddr_in *>(paddr);
        memcpy(addr.GetRaw(), pchIPv4, 12);
        memcpy(addr.GetRaw()+12, (const uint8_t*)&paddr4->sin_addr, 4);
        addr.SetPort(ntohs(paddr4->sin_port));
        return true;
    }
    case AF_INET6: {
        addr = CService(CNetBackendTcp::instance);
        const auto paddr6 = reinterpret_cast<const struct sockaddr_in6 *>(paddr);
        memcpy(addr.GetRaw(), (const uint8_t*)&paddr6->sin6_addr, 16);
        addr.SetScopeId(paddr6->sin6_scope_id);
        addr.SetPort(ntohs(paddr6->sin6_port));
        return true;
    }
    default:
        return false;
    }
}

// private extensions to enum Network, only returned by GetExtNetwork,
// and only used in GetReachabilityFrom
static const int NET_UNKNOWN = NET_MAX + 0;
static const int NET_TEREDO  = NET_MAX + 1;
int static GetExtNetwork(const CNetAddr& addr)
{
    if (IsRFC4380(addr))
        return NET_TEREDO;
    return addr.GetNetwork();
}

// ----------------

const CNetBackendTcp CNetBackendTcp::instance{};

CService CNetBackendTcp::addr_create(const ::in_addr& ipv4Addr,
                                     unsigned short portIn) const
{
    CService addr{*this};
    memcpy(addr.GetRaw(), pchIPv4, 12);
    memcpy(addr.GetRaw()+12, reinterpret_cast<const uint8_t*>(&ipv4Addr), 4);
    addr.SetPort(portIn);
    return addr;
}

CService CNetBackendTcp::addr_create(const ::in6_addr& ipv6Addr,
                                     unsigned short portIn) const
{
    CService addr{*this};
    memcpy(addr.GetRaw(), reinterpret_cast<const uint8_t*>(&ipv6Addr), 16);
    addr.SetPort(portIn);
    return addr;
}

// Lookup service endpoints by name.
bool CNetBackendTcp::lookup(const char *pszName,
                            std::vector<CNetAddr>& vIP,
                            unsigned int nMaxSolutions,
                            bool fAllowLookup) const
{
    const std::string strName{pszName};
    // Special case: Tor address.
    if (strName.size()>6 && strName.substr(strName.size() - 6, 6) == ".onion") {
        const std::vector<unsigned char> vchAddr =
            DecodeBase32(strName.substr(0, strName.size() - 6).c_str());
        if (vchAddr.size() != 16-sizeof(pchOnionCat))
            return false;
        CNetAddr addr{*this};
        memcpy(addr.GetRaw(), pchOnionCat, sizeof(pchOnionCat));
        for (unsigned int i=0; i<16-sizeof(pchOnionCat); i++)
            addr.GetRaw()[i + sizeof(pchOnionCat)] = vchAddr[i];
        vIP.push_back(addr);
        return true;
    }

    struct addrinfo aiHint;
    memset(&aiHint, 0, sizeof(struct addrinfo));

    aiHint.ai_socktype = SOCK_STREAM;
    aiHint.ai_protocol = IPPROTO_TCP;
    aiHint.ai_family = AF_UNSPEC;
#ifdef WIN32
    aiHint.ai_flags = fAllowLookup ? 0 : AI_NUMERICHOST;
#else
    aiHint.ai_flags = fAllowLookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
#endif
    struct addrinfo *aiRes = NULL;
    int nErr = getaddrinfo(pszName, NULL, &aiHint, &aiRes);
    if (nErr)
        return false;

    bool fAdded = false;
    struct addrinfo *aiTrav = aiRes;
    while (aiTrav != NULL && (nMaxSolutions == 0 || vIP.size() < nMaxSolutions))
    {
        if (aiTrav->ai_family == AF_INET)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in));
            CService addr{*this};
            SetSockAddr(addr, aiTrav->ai_addr);
            vIP.push_back(addr);
            fAdded = true;
        }

        if (aiTrav->ai_family == AF_INET6)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in6));
            CService addr{*this};
            SetSockAddr(addr, aiTrav->ai_addr);
            vIP.push_back(addr);
            fAdded = true;
        }

        aiTrav = aiTrav->ai_next;
    }

    freeaddrinfo(aiRes);

    return fAdded;
}

boost::optional<std::string> CNetBackendTcp::lookup(const CService& addr) const
{
    if (IsTor(addr))
        return boost::none;
    struct sockaddr_storage sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    if (GetSockAddr(addr, (struct sockaddr*)&sockaddr, &socklen)) {
        char name[1025] = "";
        if (!getnameinfo((const struct sockaddr*)&sockaddr,
            socklen, name, sizeof(name), NULL, 0, NI_NUMERICHOST))
            return std::string(name);
    }
    return boost::none;
}

// Create listener for specified endpoint address.
CNetBackendTcp::listener_type CNetBackendTcp::listen(const CService& addrBind) const
{
    assert(&addrBind.GetBackend() == this);

    std::string strError;
    int nOne = 1;

    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!GetSockAddr(addrBind, (struct sockaddr*)&sockaddr, &len))
    {
        strError = strprintf("Error: Bind address family for %s not supported", addrBind.ToString());
        throw std::runtime_error(strError);
    }

    SOCKET hListenSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %s)", NetworkErrorString(WSAGetLastError()));
        throw std::runtime_error(strError);
    }
    if (!IsSelectableSocket(hListenSocket))
    {
        strError = "Error: Couldn't create a listenable socket for incoming connections";
        throw std::runtime_error(strError);
    }


#ifndef WIN32
#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hListenSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&nOne, sizeof(int));
#endif
    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (void*)&nOne, sizeof(int));
    // Disable Nagle's algorithm
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&nOne, sizeof(int));
#else
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&nOne, sizeof(int));
    setsockopt(hListenSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&nOne, sizeof(int));
#endif

    // Set to non-blocking, incoming connections will also inherit this
    if (!SetSocketNonBlocking(hListenSocket, true)) {
        strError = strprintf("BindListenPort: Setting listening socket to non-blocking failed, error %s\n", NetworkErrorString(WSAGetLastError()));
        throw std::runtime_error(strError);
    }

    // some systems don't have IPV6_V6ONLY but are always v6only; others do have the option
    // and enable it by default or not. Try to enable it, if possible.
    if (IsIPv6(addrBind)) {
#ifdef IPV6_V6ONLY
#ifdef WIN32
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&nOne, sizeof(int));
#else
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&nOne, sizeof(int));
#endif
#endif
#ifdef WIN32
        int nProtLevel = PROTECTION_LEVEL_UNRESTRICTED;
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, (const char*)&nProtLevel, sizeof(int));
#endif
    }

    if (::bind(hListenSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf(_("Unable to bind to %s on this computer. %s is probably already running."), addrBind.ToString(), _(PACKAGE_NAME));
        else
            strError = strprintf(_("Unable to bind to %s on this computer (bind returned error %s)"), addrBind.ToString(), NetworkErrorString(nErr));
        CloseSocket(hListenSocket);
        throw std::runtime_error(strError);
    }
    LogPrintf("Bound to %s\n", addrBind.ToString());

    // Listen for incoming connections
    if (::listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf(_("Error: Listening for incoming connections failed (listen returned error %s)"), NetworkErrorString(WSAGetLastError()));
        CloseSocket(hListenSocket);
        throw std::runtime_error(strError);
    }

    return hListenSocket;
}

// Accept new incoming connection on listener.
CNetBackendTcp::connection_type CNetBackendTcp::accept(listener_type socketListen,
                                                       CService& addrAccept) const
{
    assert(&addrAccept.GetBackend() == this);

    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    SOCKET hSocket = ::accept(socketListen,
                            reinterpret_cast<struct sockaddr*>(&sockaddr),
                            &len);
    if (hSocket != INVALID_SOCKET)
        if (!SetSockAddr(addrAccept, (const struct sockaddr*)&sockaddr))
            LogPrintf("Warning: Unknown socket family\n");

    if (hSocket == INVALID_SOCKET)
    {
        int nErr = WSAGetLastError();
        if (nErr != WSAEWOULDBLOCK)
            LogPrintf("socket error accept failed: %s\n", NetworkErrorString(nErr));
        return INVALID_SOCKET;
    }

    if (!IsSelectableSocket(hSocket))
    {
        LogPrintf("connection from %s dropped: non-selectable socket\n", addrAccept.ToString());
        close_listener(hSocket);
        return INVALID_SOCKET;
    }

    // According to the internet TCP_NODELAY is not carried into accepted sockets
    // on all platforms.  Set it again here just to be sure.
    int set = 1;
#ifdef WIN32
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
#else
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&set, sizeof(int));
#endif

    return hSocket;
}

// Initiate new outgoing connnection.
CNetBackendTcp::connection_type CNetBackendTcp::connect(const CService& addrConnect,
                                                        int nTimeout) const
{
    assert(&addrConnect.GetBackend() == this);

    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!GetSockAddr(addrConnect, (struct sockaddr*)&sockaddr, &len)) {
        LogPrintf("Cannot connect to %s: unsupported network\n", addrConnect.ToString());
        return INVALID_SOCKET;
    }

    SOCKET hSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET)
        return INVALID_SOCKET;

    int set = 1;
#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif

    //Disable Nagle's algorithm
#ifdef WIN32
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&set, sizeof(int));
#else
    setsockopt(hSocket, IPPROTO_TCP, TCP_NODELAY, (void*)&set, sizeof(int));
#endif

    // Set to non-blocking
    if (!SetSocketNonBlocking(hSocket, true)) {
        LogPrintf("ERROR: ConnectSocketDirectly: Setting socket to non-blocking failed, error %s\n", NetworkErrorString(WSAGetLastError()));
        return INVALID_SOCKET;
    }

    if (::connect(hSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        // WSAEINVAL is here because some legacy version of winsock uses it
        if (nErr == WSAEINPROGRESS || nErr == WSAEWOULDBLOCK || nErr == WSAEINVAL)
        {
            struct timeval timeout = MillisToTimeval(nTimeout);
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(hSocket, &fdset);
            int nRet = select(hSocket + 1, NULL, &fdset, NULL, &timeout);
            if (nRet == 0)
            {
                LogPrint("net", "connection to %s timeout\n", addrConnect.ToString());
                close_connection(hSocket);
                return INVALID_SOCKET;
            }
            if (nRet == SOCKET_ERROR)
            {
                LogPrintf("select() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                close_connection(hSocket);
                return INVALID_SOCKET;
            }
            socklen_t nRetSize = sizeof(nRet);
#ifdef WIN32
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, (char*)(&nRet), &nRetSize) == SOCKET_ERROR)
#else
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, &nRet, &nRetSize) == SOCKET_ERROR)
#endif
            {
                LogPrintf("getsockopt() for %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
                close_connection(hSocket);
                return INVALID_SOCKET;
            }
            if (nRet != 0)
            {
                LogPrintf("connect() to %s failed after select(): %s\n", addrConnect.ToString(), NetworkErrorString(nRet));
                close_connection(hSocket);
                return INVALID_SOCKET;
            }
        }
#ifdef WIN32
        else if (WSAGetLastError() != WSAEISCONN)
#else
        else
#endif
        {
            LogPrintf("connect() to %s failed: %s\n", addrConnect.ToString(), NetworkErrorString(WSAGetLastError()));
            close_connection(hSocket);
            return INVALID_SOCKET;
        }
    }

    return hSocket;
}

// Send raw data to connection.
ssize_t CNetBackendTcp::send(connection_type socket,
                             const char *data,
                             size_t size) const
{
    return ::send(socket, data, size, MSG_NOSIGNAL | MSG_DONTWAIT);
}

// Receive raw data from connection.
ssize_t CNetBackendTcp::recv(connection_type socket,
                             char *data,
                             size_t size) const
{
    return ::recv(socket, data, size, MSG_DONTWAIT);
}

// Close listener.
bool CNetBackendTcp::close_listener(listener_type socketListen) const
{
    if (socketListen == INVALID_SOCKET)
        return false;
#ifdef WIN32
    int ret = closesocket(socketListen);
#else
    int ret = close(socketListen);
#endif
    return ret != SOCKET_ERROR;
}

// Close connection.
bool CNetBackendTcp::close_connection(connection_type socket) const
{
    if (socket == INVALID_SOCKET)
        return false;
#ifdef WIN32
    int ret = closesocket(socket);
#else
    int ret = close(socket);
#endif
    return ret != SOCKET_ERROR;
}

bool CNetBackendTcp::addr_is_local(const CNetAddr& addr) const
{
    assert(&addr.GetBackend() == this);

    // IPv4 loopback
   if (IsIPv4(addr) && (addr.GetByte(3) == 127 || addr.GetByte(3) == 0))
       return true;

   // IPv6 loopback (::1/128)
   static const unsigned char pchLocal[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
   if (memcmp(addr.GetRaw(), pchLocal, 16) == 0)
       return true;

   return false;
}

bool CNetBackendTcp::addr_is_multicast(const CNetAddr& addr) const
{
    assert(&addr.GetBackend() == this);
    return    (IsIPv4(addr) && (addr.GetByte(3) & 0xF0) == 0xE0)
           || (addr.GetByte(15) == 0xFF);
}

bool CNetBackendTcp::addr_is_valid(const CNetAddr& addr) const
{
    assert(&addr.GetBackend() == this);

    // Cleanup 3-byte shifted addresses caused by garbage in size field
    // of addr messages from versions before 0.2.9 checksum.
    // Two consecutive addr messages look like this:
    // header20 vectorlen3 addr26 addr26 addr26 header20 vectorlen3 addr26 addr26 addr26...
    // so if the first length field is garbled, it reads the second batch
    // of addr misaligned by 3 bytes.
    if (memcmp(addr.GetRaw(), pchIPv4+3, sizeof(pchIPv4)-3) == 0)
        return false;

    // unspecified IPv6 address (::/128)
    unsigned char ipNone6[16] = {};
    if (memcmp(addr.GetRaw(), ipNone6, 16) == 0)
        return false;

    // documentation IPv6 address
    if (IsRFC3849(addr))
        return false;

    if (IsIPv4(addr))
    {
        // INADDR_NONE
        uint32_t ipNone = INADDR_NONE;
        if (memcmp(addr.GetRaw()+12, &ipNone, 4) == 0)
            return false;

        // 0
        ipNone = 0;
        if (memcmp(addr.GetRaw()+12, &ipNone, 4) == 0)
            return false;
    }

    return true;
}

bool CNetBackendTcp::addr_is_routable(const CNetAddr& addr) const
{
    assert(&addr.GetBackend() == this);
    if (!addr_is_valid(addr))
        return false;
    if (!fAllowPrivateNet && IsRFC1918(addr))
        return false;
    return !(IsRFC2544(addr) || IsRFC3927(addr) || IsRFC4862(addr) ||
             IsRFC6598(addr) || IsRFC5737(addr) ||
             (IsRFC4193(addr) && !IsTor(addr)) || IsRFC4843(addr) ||
             addr_is_local(addr));
}

std::string CNetBackendTcp::addr_str(const CNetAddr& addr) const
{
    if (IsTor(addr))
        return EncodeBase32(addr.GetRaw() + 6, 10) + ".onion";
    if (IsIPv4(addr))
        return strprintf("%u.%u.%u.%u",
                         addr.GetByte(3), addr.GetByte(2),
                         addr.GetByte(1), addr.GetByte(0));
    else
        return strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                         addr.GetByte(15) << 8 | addr.GetByte(14),
                         addr.GetByte(13) << 8 | addr.GetByte(12),
                         addr.GetByte(11) << 8 | addr.GetByte(10),
                         addr.GetByte(9) << 8 | addr.GetByte(8),
                         addr.GetByte(7) << 8 | addr.GetByte(6),
                         addr.GetByte(5) << 8 | addr.GetByte(4),
                         addr.GetByte(3) << 8 | addr.GetByte(2),
                         addr.GetByte(1) << 8 | addr.GetByte(0));
}

std::vector<unsigned char> CNetBackendTcp::addr_group(const CNetAddr& addr) const
{
    std::vector<unsigned char> vchRet;
    int nClass = NET_IPV6;
    int nStartByte = 0;
    int nBits = 16;

    // all local addresses belong to the same group
    if (addr_is_local(addr)) {
        nClass = 255;
        nBits = 0;
    }

    // all unroutable addresses belong to the same group
    if (!addr_is_routable(addr)) {
        nClass = NET_UNROUTABLE;
        nBits = 0;
    }
    // for IPv4 addresses, '1' + the 16 higher-order bits of the IP
    // includes mapped IPv4, SIIT translated IPv4, and the well-known prefix
    else if (IsIPv4(addr) || IsRFC6145(addr) || IsRFC6052(addr)) {
        nClass = NET_IPV4;
        nStartByte = 12;
    }
    // for 6to4 tunnelled addresses, use the encapsulated IPv4 address
    else if (IsRFC3964(addr)) {
        nClass = NET_IPV4;
        nStartByte = 2;
    }
    // for Teredo-tunnelled IPv6 addresses, use the encapsulated IPv4 address
    else if (IsRFC4380(addr)) {
        vchRet.push_back(NET_IPV4);
        vchRet.push_back(addr.GetByte(3) ^ 0xFF);
        vchRet.push_back(addr.GetByte(2) ^ 0xFF);
        return vchRet;
    }
    else if (IsTor(addr)) {
        nClass = NET_TOR;
        nStartByte = 6;
        nBits = 4;
    }
    // for he.net, use /36 groups
    else if (addr.GetByte(15) == 0x20 && addr.GetByte(14) == 0x01 &&
             addr.GetByte(13) == 0x04 && addr.GetByte(12) == 0x70)
        nBits = 36;
    // for the rest of the IPv6 network, use /32 groups
    else
        nBits = 32;

    vchRet.push_back(nClass);
    while (nBits >= 8) {
        vchRet.push_back(addr.GetByte(15 - nStartByte));
        nStartByte++;
        nBits -= 8;
    }
    if (nBits > 0)
        vchRet.push_back(addr.GetByte(15 - nStartByte) | ((1 << (8 - nBits)) - 1));

    return vchRet;
}

int CNetBackendTcp::addr_reachability(const CNetAddr& ouraddr,
                                      const CNetAddr& theiraddr) const
{
    assert(&ouraddr.GetBackend() == this);
    if (&theiraddr.GetBackend() != this)
        return -1;

    enum Reachability {
        REACH_UNREACHABLE,
        REACH_DEFAULT,
        REACH_TEREDO,
        REACH_IPV6_WEAK,
        REACH_IPV4,
        REACH_IPV6_STRONG,
        REACH_PRIVATE
    };

    if (!addr_is_routable(ouraddr))
        return REACH_UNREACHABLE;

    int ourNet = GetExtNetwork(ouraddr);
    int theirNet = GetExtNetwork(theiraddr);
    bool fTunnel = IsRFC3964(ouraddr) || IsRFC6052(ouraddr) || IsRFC6145(ouraddr);

    switch(theirNet) {
    case NET_IPV4:
        switch(ourNet) {
        default:       return REACH_DEFAULT;
        case NET_IPV4: return REACH_IPV4;
        }
    case NET_IPV6:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_TEREDO: return REACH_TEREDO;
        case NET_IPV4:   return REACH_IPV4;
        case NET_IPV6:   return fTunnel ? REACH_IPV6_WEAK : REACH_IPV6_STRONG; // only prefer giving our IPv6 address if it's not tunnelled
        }
    case NET_TOR:
        switch(ourNet) {
        default:         return REACH_DEFAULT;
        case NET_IPV4:   return REACH_IPV4; // Tor users can connect to IPv4 as well
        case NET_TOR:    return REACH_PRIVATE;
        }
    case NET_TEREDO:
        switch(ourNet) {
        default:          return REACH_DEFAULT;
        case NET_TEREDO:  return REACH_TEREDO;
        case NET_IPV6:    return REACH_IPV6_WEAK;
        case NET_IPV4:    return REACH_IPV4;
        }
    case NET_UNKNOWN:
    case NET_UNROUTABLE:
    default:
        switch(ourNet) {
        default:          return REACH_DEFAULT;
        case NET_TEREDO:  return REACH_TEREDO;
        case NET_IPV6:    return REACH_IPV6_WEAK;
        case NET_IPV4:    return REACH_IPV4;
        case NET_TOR:     return REACH_PRIVATE; // either from Tor, or don't care about our address
        }
    }
}

std::vector<CService> CNetBackendTcp::bind_any_addrs() const
{
    CService addr6{*this};
    CService addr4{*this};
    {
        ::sockaddr_in6 sockaddr6;
        memset(&sockaddr6, 0, sizeof sockaddr6);
        sockaddr6.sin6_family = AF_INET;
        sockaddr6.sin6_addr = in6addr_any;
        sockaddr6.sin6_port = htons(0);
        sockaddr6.sin6_scope_id = 0;
        SetSockAddr(addr6, reinterpret_cast<const ::sockaddr *>(&sockaddr6));
    }
    {
        ::sockaddr_in sockaddr4;
        memset(&sockaddr4, 0, sizeof sockaddr4);
        sockaddr4.sin_family = AF_INET;
        sockaddr4.sin_addr.s_addr = INADDR_ANY;
        sockaddr4.sin_port = htons(0);
        SetSockAddr(addr4, reinterpret_cast<const ::sockaddr *>(&sockaddr4));
    }
    return {addr6, addr4};
}

std::vector<CService> CNetBackendTcp::local_if_addrs() const
{
    std::vector<CService> addrs;
#ifdef WIN32
    // Get local host IP
    char pszHostName[256] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        std::vector<CNetAddr> vaddr;
        if (LookupHost(pszHostName, vaddr, 0, true))
        {
            std::transform(vaddr.begin(), vaddr.end(), addrs.end(),
                           [](const CNetAddr& addr){return CService(addr, 0);});
        }
    }
#else
    // Get local host ip
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == NULL) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (strcmp(ifa->ifa_name, "lo0") == 0) continue;
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                ::sockaddr_in* s4 = (::sockaddr_in*)(ifa->ifa_addr);
                addrs.push_back(addr_create(s4->sin_addr, 0));
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                ::sockaddr_in6* s6 = (::sockaddr_in6*)(ifa->ifa_addr);
                addrs.push_back(addr_create(s6->sin6_addr, 0));
            }
        }
        freeifaddrs(myaddrs);
    }
#endif
}
