// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NETBACKEND_TCP_H
#define NETBACKEND_TCP_H

#include "netbackend.h"

struct in_addr;
struct in6_addr;

//! Network backend providing TCP connection.
class CNetBackendTcp: public CNetBackend {

    // Private constructor for making this class a singleton.
    CNetBackendTcp() {}

public:

    //! CNetBackendTcp singleton instance.
    static const CNetBackendTcp instance;

    //! Create endpoint address from IPv4 address and port number.
    //! @param[in] ipv4Addr IPv4 address
    //! @param[in] portIn port number
    //! @return endpoint address for given IPv4 address and port number
    CService addr_create(const ::in_addr& ipv4Addr,
                         unsigned short portIn) const;

    //! Create endpoint address from IPv6 address and port number.
    //! @param[in] ipv6Addr IPv6 address
    //! @param[in] portIn port number
    //! @return endpoint address for given IPv6 address and port number
    CService addr_create(const ::in6_addr& ipv6Addr,
                         unsigned short portIn) const;

    // Name of the backend.
    const char *name() const override {return "tcp";}

    // Lookup service endpoints by name.
    bool lookup(const char *pszName,
                std::vector<CNetAddr>& vIP,
                unsigned int nMaxSolutions,
                bool fAllowLookup) const override;

    // Lookup service name by endpoint address.
    boost::optional<std::string> lookup(const CService& addr) const override;

    // Create listener for specified endpoint address.
    listener_type listen(const CService& addrBind) const override;

    // Accept new incoming connection on listener.
    connection_type accept(listener_type socketListen,
                           CService& addrAccept) const override;

    // Initiate new outgoing connnection.
    connection_type connect(const CService& addrConnect,
                            int nTimeout) const override;

    // Send raw data to connection.
    ssize_t send(connection_type socket,
                 const char *data,
                 size_t size) const override;

    // Receive raw data from connection.
    ssize_t recv(connection_type socket,
                 char *data,
                 size_t size) const override;

    // Close listener.
    bool close_listener(listener_type socketListen) const override;

    // Close connection.
    bool close_connection(connection_type socket) const override;

    // Check whether address is local.
    bool addr_is_local(const CNetAddr& addr) const override;

    // Check whether address is multicast.
    bool addr_is_multicast(const CNetAddr& addr) const override;

    // Check whether address is valid.
    bool addr_is_valid(const CNetAddr& addr) const override;

    // Check whether address is routable.
    bool addr_is_routable(const CNetAddr& addr) const override;

    // String representation of address.
    std::string addr_str(const CNetAddr& addr) const override;

    // Address group.
    std::vector<unsigned char> addr_group(const CNetAddr& addr) const override;

    // Reachability score between two nodes specified by their addresses.
    int addr_reachability(const CNetAddr& ouraddr,
                          const CNetAddr& theiraddr) const override;

    // Addresses for this backend to bind to any local interface.
    std::vector<CService> bind_any_addrs() const override;

    // All local addresses for this host.
    std::vector<CService> local_if_addrs() const override;
};

#endif
