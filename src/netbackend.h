// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NETBACKEND_H
#define NETBACKEND_H

#include <vector>
#include <string>
#include <boost/optional.hpp>

#include "netaddress.h"
#include "compat.h"

class CService;

//! Abstract network backend.
class CNetBackend {
protected:
    CNetBackend();

public:
    //! Type of file descriptor representing network connnection.
    using connection_type = SOCKET;

    //! Type of file descriptor representing listener for new connections.
    using listener_type = SOCKET;

    //! Maximum size of address data in bytes.
    constexpr static const unsigned int MAX_ADDRESS_SIZE = 16;

    //! Type of container where all available backends are registered.
    using all_t = std::vector<std::reference_wrapper<const CNetBackend>>;

    //! Destructor
    virtual ~CNetBackend() {}

    //! All available network backends.
    //! @return reference to container where all available backends are registered
    static const all_t& all();

    //! Name of the backend.
    //! @return name of the backend
    virtual const char *name() const = 0;

    //! Lookup service endpoints by name.
    //! @param[in] pszName string representation of endpoint name
    //! @param[in] nMaxSolitions maximum number of returned endpoints
    //! @param[in] fAllowLookup allow name loookup (use address otherwise)
    //! @param[out] vector where to add endpoint addresses
    //! @return true if lookup was successful
    virtual bool lookup(const char *pszName,
                        std::vector<CNetAddr>& vIP,
                        unsigned int nMaxSolutions,
                        bool fAllowLookup) const = 0;

    //! Lookup service name by endpoint address.
    //! @param[in] addr address of endpoint to lookup
    //! @return name corresponding to address or boost::none if not found
    virtual boost::optional<std::string> lookup(const CService& addr) const = 0;

    //! Create listener for specified endpoint address.
    //! @param[in] addrBind endpoint address to listen on
    //! @return descriptor of listener
    virtual listener_type listen(const CService &addrBind) const = 0;

    //! Accept new incoming connection on listener.
    //! @param[in] socketListen descriptor of listener to accept connection on
    //! @param[out] addrAccept endpoint address for incoming connection
    //! @return descriptor of established incoming connnection
    virtual connection_type accept(listener_type socketListen,
                                   CService& addrAccept) const = 0;

    //! Initiate new outgoing connnection.
    //! @param[in] addrConnect address of endpoint to connect to
    //! @param[in] nTimeout timeout in milliseconds
    //! @return descriptor of established outgoing connection
    virtual connection_type connect(const CService &addrConnect,
                                    int nTimeout) const = 0;

    //! Send raw data to connection.
    //! @param[in] socket descriptor of connection
    //! @param[in] data raw data to send
    //! @param[in] size size of raw data to send
    //! @return size of data that was actually sent
    virtual ssize_t send(connection_type socket,
                         const char *data,
                         size_t size) const = 0;

    //! Receive raw data from connection.
    //! @param[in] socket descriptor of connection
    //! @param[in] data buffer foor raw data to receive
    //! @param[in] size maximum size of raw data to receive
    //! @return size of data that was actually received
    virtual ssize_t recv(connection_type socket,
                         char *data,
                         size_t size) const = 0;

    //! Close listener.
    //! @param[in] socketListen descriptor of listener to close
    //! @return whether closing was successful
    virtual bool close_listener(listener_type socketListen) const = 0;

    //! Close connection.
    //! @param[in] socket descriptor of connection to close
    //! @return whether closing was successful
    virtual bool close_connection(connection_type socket) const = 0;

    //! Check whether address is local.
    //! @param[in] addr address to check
    //! @return true if address is local
    virtual bool addr_is_local(const CNetAddr& addr) const = 0;

    //! Check whether address is multicast.
    //! @param[in] addr address to check
    //! @return true if address is multicast
    virtual bool addr_is_multicast(const CNetAddr& addr) const = 0;

    //! Check whether address is valid.
    //! @param[in] addr address to check
    //! @return true if address is valid
    virtual bool addr_is_valid(const CNetAddr& addr) const = 0;

    //! Check whether address is routable.
    //! @param[in] addr address to check
    //! @return true if address is routable
    virtual bool addr_is_routable(const CNetAddr& addr) const = 0;

    //! String representation of address.
    //! @param[in] addr address to convert to string
    //! @return readable string representation of the address
    virtual std::string addr_str(const CNetAddr& addr) const = 0;

    //! Address group.
    //! @param[in] addr address to get group of
    //! @return group corrresponding to the address
    virtual std::vector<unsigned char> addr_group(const CNetAddr& addr) const = 0;

    //! Reachability score between two nodes specified by their addresses.
    //! @param[in] ouraddr address of our node
    //! @param[in] theiraddr address of partner node
    //! @return score of reachability between these nodes (greater is better)
    virtual int addr_reachability(const CNetAddr& ouraddr,
                                  const CNetAddr& theiraddr) const = 0;

    //! Addresses for this backend to bind to any local interface.
    //! @return vector with local addresses
    virtual std::vector<CService> bind_any_addrs() const = 0;

    //! All local addresses for this host.
    //! @return vector with local addresses
    virtual std::vector<CService> local_if_addrs() const = 0;
};

#endif
