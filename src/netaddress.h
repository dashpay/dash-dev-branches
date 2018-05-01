// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETADDRESS_H
#define BITCOIN_NETADDRESS_H

#if defined(HAVE_CONFIG_H)
#include "config/dash-config.h"
#endif

#include "compat.h"
#include "serialize.h"

#include <stdint.h>
#include <string>
#include <vector>
#include <array>

extern bool fAllowPrivateNet;

class CNetBackend;

enum Network
{
    NET_UNROUTABLE = 0,
    NET_IPV4,
    NET_IPV6,
    NET_TOR,
    NET_OTHER,

    NET_MAX,
};

/** Address group */
class CNetAddrGroup
{
    const CNetBackend *backend;
    const std::vector<unsigned char> data;
public:
    CNetAddrGroup(const CNetBackend& backendIn,
                  const std::vector<unsigned char>& dataIn)
    : backend(&backendIn), data(dataIn) {}
    const CNetBackend& GetBackend() const {return *backend;}
    const char *GetBackendName() const;
    const std::vector<unsigned char>& GetData() const {return data;}

    template <typename Stream> void Serialize(Stream& s) const {
        std::string strName(GetBackendName());
        ::Serialize(s, strName);
        ::Serialize(s, data);
    }
};

inline bool operator==(const CNetAddrGroup& l, const CNetAddrGroup& r)
{
    return &l.GetBackend() == &r.GetBackend() && l.GetData() == r.GetData();
}

inline bool operator<(const CNetAddrGroup& l, const CNetAddrGroup& r)
{
    return &l.GetBackend() < &r.GetBackend() ||
           (&l.GetBackend() == &r.GetBackend() && l.GetData() < r.GetData());
}

/** IP address (IPv6, or IPv4 using mapped IPv6 range (::FFFF:0:0/96)) */
class CNetAddr
{
    public:
        using DataType = std::array<unsigned char, 16>;

    private:
        const CNetBackend *backend;
        DataType ip; // in network byte order
        uint32_t scopeId; // for scoped/link-local ipv6 addresses

    public:
        CNetAddr();
        CNetAddr(const CNetBackend& netbackend);
        void SetIP(const CNetAddr& ip);

        const DataType& GetRaw() const {return ip;}
        DataType& GetRaw() {return ip;}
        uint32_t GetScopeId() const {return scopeId;}
        void SetScopeId(uint32_t scopeIdIn) {scopeId = scopeIdIn;}

        bool IsIPv4() const;    // IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
        bool IsIPv6() const;    // IPv6 address (not mapped IPv4, not Tor)
        bool IsPrivate() const; // private networks
        bool IsTor() const;
        bool IsLocal() const;
        bool IsRoutable() const;
        bool IsValid() const;
        bool IsMulticast() const;
        const CNetBackend& GetBackend() const {return *backend;}
        enum Network GetNetwork() const;
        std::string ToString() const;
        std::string ToStringIP(bool fUseGetnameinfo = true) const;
        uint64_t GetHash() const;
        CNetAddrGroup GetGroup() const;
        int GetReachabilityFrom(const CNetAddr *paddrPartner = NULL) const;

        friend bool operator==(const CNetAddr& a, const CNetAddr& b);
        friend bool operator!=(const CNetAddr& a, const CNetAddr& b);
        friend bool operator<(const CNetAddr& a, const CNetAddr& b);

        template<typename Stream>
        void Serialize(Stream& s) const
        {
            s.write(reinterpret_cast<const char *>(ip.data()), ip.size());
        }

        template<typename Stream>
        void Unserialize(Stream& s)
        {
            s.read(reinterpret_cast<char *>(ip.data()), ip.size());
        }

        friend class CSubNet;
};

class CSubNet
{
    protected:
        /// Network (base) address
        CNetAddr network;
        /// Netmask, in network byte order
        uint8_t netmask[16];
        /// Is this value valid? (only used to signal parse errors)
        bool valid;

    public:
        CSubNet();
        CSubNet(const CNetAddr &addr, int32_t mask);
        CSubNet(const CNetAddr &addr, const CNetAddr &mask);

        //constructor for single ip subnet (<ipv4>/32 or <ipv6>/128)
        explicit CSubNet(const CNetAddr &addr);

        bool Match(const CNetAddr &addr) const;

        std::string ToString() const;
        bool IsValid() const;

        friend bool operator==(const CSubNet& a, const CSubNet& b);
        friend bool operator!=(const CSubNet& a, const CSubNet& b);
        friend bool operator<(const CSubNet& a, const CSubNet& b);

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(network);
            READWRITE(FLATDATA(netmask));
            READWRITE(FLATDATA(valid));
        }
};

/** A combination of a network address (CNetAddr) and a (TCP) port */
class CService : public CNetAddr
{
    private:
        unsigned short port; // host order

    public:
        CService();
        CService(const CNetBackend& netbackend);
        CService(const CNetAddr& ip, unsigned short port);
        void Init();
        void SetPort(unsigned short portIn);
        unsigned short GetPort() const;
        friend bool operator==(const CService& a, const CService& b);
        friend bool operator!=(const CService& a, const CService& b);
        friend bool operator<(const CService& a, const CService& b);
        std::vector<unsigned char> GetKey() const;
        std::string ToString(bool fUseGetnameinfo = true) const;
        std::string ToStringPort() const;
        std::string ToStringIPPort(bool fUseGetnameinfo = true) const;

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(*static_cast<CNetAddr*>(this));
            unsigned short portN = htons(port);
            READWRITE(FLATDATA(portN));
            if (ser_action.ForRead())
                 port = ntohs(portN);
        }
};

#endif // BITCOIN_NETADDRESS_H
