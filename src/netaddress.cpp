// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include "config/dash-config.h"
#endif

#include "netaddress.h"
#include "netbase.h"
#include "hash.h"
#include "utilstrencodings.h"
#include "tinyformat.h"

#include "netbackend/tcp.h"

static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
static const unsigned char pchOnionCat[] = {0xFD,0x87,0xD8,0x7E,0xEB,0x43};

bool fAllowPrivateNet = DEFAULT_ALLOWPRIVATENET;

const char *CNetAddrGroup::GetBackendName() const
{
    return GetBackend().name();
}

void CNetAddr::Init()
{
    memset(ip, 0, sizeof(ip));
    scopeId = 0;
}

void CNetAddr::SetIP(const CNetAddr& ipIn)
{
    memcpy(ip, ipIn.ip, sizeof(ip));
}

CNetAddr::CNetAddr()
: backend{&CNetBackendTcp::instance}
{
    Init();
}

CNetAddr::CNetAddr(const CNetBackend& netbackend)
: backend{&netbackend}
{
    Init();
}

unsigned int CNetAddr::GetByte(int n) const
{
    return ip[15-n];
}

bool CNetAddr::IsIPv4() const
{
    return (&GetBackend() == &CNetBackendTcp::instance &&
            memcmp(ip, pchIPv4, sizeof(pchIPv4)) == 0);
}

bool CNetAddr::IsIPv6() const
{
    return (&GetBackend() == &CNetBackendTcp::instance &&
            !IsIPv4() && !IsTor());
}

bool CNetAddr::IsRFC1918() const
{
    return IsIPv4() && (
        GetByte(3) == 10 ||
        (GetByte(3) == 192 && GetByte(2) == 168) ||
        (GetByte(3) == 172 && (GetByte(2) >= 16 && GetByte(2) <= 31)));
}

bool CNetAddr::IsRFC3964() const
{
    return (&GetBackend() == &CNetBackendTcp::instance &&
            GetByte(15) == 0x20 && GetByte(14) == 0x02);
}

bool CNetAddr::IsRFC6052() const
{
    static const unsigned char pchRFC6052[] = {0,0x64,0xFF,0x9B,0,0,0,0,0,0,0,0};
    return (&GetBackend() == &CNetBackendTcp::instance &&
            memcmp(ip, pchRFC6052, sizeof(pchRFC6052)) == 0);
}

bool CNetAddr::IsRFC4380() const
{
    return (&GetBackend() == &CNetBackendTcp::instance &&
            GetByte(15) == 0x20 && GetByte(14) == 0x01 &&
            GetByte(13) == 0 && GetByte(12) == 0);
}

bool CNetAddr::IsRFC6145() const
{
    static const unsigned char pchRFC6145[] = {0,0,0,0,0,0,0,0,0xFF,0xFF,0,0};
    return (&GetBackend() == &CNetBackendTcp::instance &&
            memcmp(ip, pchRFC6145, sizeof(pchRFC6145)) == 0);
}

bool CNetAddr::IsRFC4843() const
{
    return (&GetBackend() == &CNetBackendTcp::instance &&
            GetByte(15) == 0x20 && GetByte(14) == 0x01 &&
            GetByte(13) == 0x00 && (GetByte(12) & 0xF0) == 0x10);
}

bool CNetAddr::IsTor() const
{
    return (&GetBackend() == &CNetBackendTcp::instance &&
            memcmp(ip, pchOnionCat, sizeof(pchOnionCat)) == 0);
}

bool CNetAddr::IsLocal() const
{
    return GetBackend().addr_is_local(*this);
}

bool CNetAddr::IsMulticast() const
{
    return GetBackend().addr_is_multicast(*this);
}

bool CNetAddr::IsValid() const
{
    return GetBackend().addr_is_valid(*this);
}

bool CNetAddr::IsRoutable() const
{
    return GetBackend().addr_is_routable(*this);
}

enum Network CNetAddr::GetNetwork() const
{
    if (&GetBackend() != &CNetBackendTcp::instance)
        return NET_OTHER;

    if (!IsRoutable())
        return NET_UNROUTABLE;

    if (IsIPv4())
        return NET_IPV4;

    if (IsTor())
        return NET_TOR;

    return NET_IPV6;
}

std::string CNetAddr::ToStringIP(bool fUseGetnameinfo) const
{
    if (fUseGetnameinfo) {
        CService serv(*this, 0);
        auto res = GetBackend().lookup(serv);
        if (res != boost::none)
            return *res;
    }
    return GetBackend().addr_str(*this);
}

std::string CNetAddr::ToString() const
{
    return ToStringIP();
}

bool operator==(const CNetAddr& a, const CNetAddr& b)
{
    return (&a.GetBackend() == &b.GetBackend() && memcmp(a.ip, b.ip, 16) == 0);
}

bool operator!=(const CNetAddr& a, const CNetAddr& b)
{
    return (&a.GetBackend() != &b.GetBackend() || memcmp(a.ip, b.ip, 16) != 0);
}

bool operator<(const CNetAddr& a, const CNetAddr& b)
{
    return (&a.GetBackend() < &b.GetBackend() ||
            (&a.GetBackend() == &b.GetBackend() && memcmp(a.ip, b.ip, 16) < 0));
}

// get canonical identifier of an address' group
// no two connections will be attempted to addresses with the same group
CNetAddrGroup CNetAddr::GetGroup() const
{
    return {GetBackend(), GetBackend().addr_group(*this)};
}

uint64_t CNetAddr::GetHash() const
{
    uint256 hash = Hash(&ip[0], &ip[16]);
    uint64_t nRet;
    memcpy(&nRet, &hash, sizeof(nRet));
    return nRet;
}

// private extensions to enum Network, only returned by GetExtNetwork,
// and only used in GetReachabilityFrom
static const int NET_UNKNOWN = NET_MAX + 0;
static const int NET_TEREDO  = NET_MAX + 1;
int static GetExtNetwork(const CNetAddr *addr)
{
    if (addr == NULL)
        return NET_UNKNOWN;
    if (addr->IsRFC4380())
        return NET_TEREDO;
    return addr->GetNetwork();
}

/** Calculates a metric for how reachable (*this) is from a given partner */
int CNetAddr::GetReachabilityFrom(const CNetAddr *paddrPartner) const
{
    enum Reachability {
        REACH_UNREACHABLE,
        REACH_DEFAULT,
        REACH_TEREDO,
        REACH_IPV6_WEAK,
        REACH_IPV4,
        REACH_IPV6_STRONG,
        REACH_PRIVATE
    };

    if (!IsRoutable())
        return REACH_UNREACHABLE;

    int ourNet = GetExtNetwork(this);
    int theirNet = GetExtNetwork(paddrPartner);
    bool fTunnel = IsRFC3964() || IsRFC6052() || IsRFC6145();

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

void CService::Init()
{
    port = 0;
}

CService::CService()
{
    Init();
}

CService::CService(const CNetBackend& netbackend) : CNetAddr{netbackend}
{
    Init();
}

CService::CService(const CNetAddr& cip, unsigned short portIn) : CNetAddr(cip), port(portIn)
{
}

unsigned short CService::GetPort() const
{
    return port;
}

bool operator==(const CService& a, const CService& b)
{
    return (CNetAddr)a == (CNetAddr)b && a.port == b.port;
}

bool operator!=(const CService& a, const CService& b)
{
    return (CNetAddr)a != (CNetAddr)b || a.port != b.port;
}

bool operator<(const CService& a, const CService& b)
{
    return (CNetAddr)a < (CNetAddr)b || ((CNetAddr)a == (CNetAddr)b && a.port < b.port);
}

std::vector<unsigned char> CService::GetKey() const
{
     std::vector<unsigned char> vKey;
     vKey.resize(18);
     memcpy(&vKey[0], ip, 16);
     vKey[16] = port / 0x100;
     vKey[17] = port & 0x0FF;
     return vKey;
}

std::string CService::ToStringPort() const
{
    return strprintf("%u", port);
}

std::string CService::ToStringIPPort(bool fUseGetnameinfo) const
{
    if (!IsIPv6()) {
        return ToStringIP(fUseGetnameinfo) + ":" + ToStringPort();
    } else {
        return "[" + ToStringIP(fUseGetnameinfo) + "]:" + ToStringPort();
    }
}

std::string CService::ToString(bool fUseGetnameinfo) const
{
    return ToStringIPPort(fUseGetnameinfo);
}

void CService::SetPort(unsigned short portIn)
{
    port = portIn;
}

CSubNet::CSubNet():
    valid(false)
{
    memset(netmask, 0, sizeof(netmask));
}

CSubNet::CSubNet(const CNetAddr &addr, int32_t mask)
{
    valid = true;
    network = addr;
    // Default to /32 (IPv4) or /128 (IPv6), i.e. match single address
    memset(netmask, 255, sizeof(netmask));

    // IPv4 addresses start at offset 12, and first 12 bytes must match, so just offset n
    const int astartofs = network.IsIPv4() ? 12 : 0;

    int32_t n = mask;
    if(n >= 0 && n <= (128 - astartofs*8)) // Only valid if in range of bits of address
    {
        n += astartofs*8;
        // Clear bits [n..127]
        for (; n < 128; ++n)
            netmask[n>>3] &= ~(1<<(7-(n&7)));
    } else
        valid = false;

    // Normalize network according to netmask
    for(int x=0; x<16; ++x)
        network.ip[x] &= netmask[x];
}

CSubNet::CSubNet(const CNetAddr &addr, const CNetAddr &mask)
{
    valid = true;
    network = addr;
    // Default to /32 (IPv4) or /128 (IPv6), i.e. match single address
    memset(netmask, 255, sizeof(netmask));

    // IPv4 addresses start at offset 12, and first 12 bytes must match, so just offset n
    const int astartofs = network.IsIPv4() ? 12 : 0;

    for(int x=astartofs; x<16; ++x)
        netmask[x] = mask.ip[x];

    // Normalize network according to netmask
    for(int x=0; x<16; ++x)
        network.ip[x] &= netmask[x];
}

CSubNet::CSubNet(const CNetAddr &addr):
    valid(addr.IsValid())
{
    memset(netmask, 255, sizeof(netmask));
    network = addr;
}

bool CSubNet::Match(const CNetAddr &addr) const
{
    if (!valid || !addr.IsValid())
        return false;
    for(int x=0; x<16; ++x)
        if ((addr.ip[x] & netmask[x]) != network.ip[x])
            return false;
    return true;
}

static inline int NetmaskBits(uint8_t x)
{
    switch(x) {
    case 0x00: return 0; break;
    case 0x80: return 1; break;
    case 0xc0: return 2; break;
    case 0xe0: return 3; break;
    case 0xf0: return 4; break;
    case 0xf8: return 5; break;
    case 0xfc: return 6; break;
    case 0xfe: return 7; break;
    case 0xff: return 8; break;
    default: return -1; break;
    }
}

std::string CSubNet::ToString() const
{
    /* Parse binary 1{n}0{N-n} to see if mask can be represented as /n */
    int cidr = 0;
    bool valid_cidr = true;
    int n = network.IsIPv4() ? 12 : 0;
    for (; n < 16 && netmask[n] == 0xff; ++n)
        cidr += 8;
    if (n < 16) {
        int bits = NetmaskBits(netmask[n]);
        if (bits < 0)
            valid_cidr = false;
        else
            cidr += bits;
        ++n;
    }
    for (; n < 16 && valid_cidr; ++n)
        if (netmask[n] != 0x00)
            valid_cidr = false;

    /* Format output */
    std::string strNetmask;
    if (valid_cidr) {
        strNetmask = strprintf("%u", cidr);
    } else {
        if (network.IsIPv4())
            strNetmask = strprintf("%u.%u.%u.%u", netmask[12], netmask[13], netmask[14], netmask[15]);
        else
            strNetmask = strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                             netmask[0] << 8 | netmask[1], netmask[2] << 8 | netmask[3],
                             netmask[4] << 8 | netmask[5], netmask[6] << 8 | netmask[7],
                             netmask[8] << 8 | netmask[9], netmask[10] << 8 | netmask[11],
                             netmask[12] << 8 | netmask[13], netmask[14] << 8 | netmask[15]);
    }

    return network.ToString() + "/" + strNetmask;
}

bool CSubNet::IsValid() const
{
    return valid;
}

bool operator==(const CSubNet& a, const CSubNet& b)
{
    return a.valid == b.valid && a.network == b.network && !memcmp(a.netmask, b.netmask, 16);
}

bool operator!=(const CSubNet& a, const CSubNet& b)
{
    return !(a==b);
}

bool operator<(const CSubNet& a, const CSubNet& b)
{
    return (a.network < b.network || (a.network == b.network && memcmp(a.netmask, b.netmask, 16) < 0));
}
