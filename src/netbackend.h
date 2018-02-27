// Copyright (c) 2018 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NETBACKEND_H
#define NETBACKEND_H

#include <vector>

#include "netaddress.h"
#include "compat.h"

class CService;

//! Abstract network backend.
class CNetBackend {
public:
    //! Type of file descriptor representing network connnection.
    using connection_type = SOCKET;

    //! Type of file descriptor representing listener for new connections.
    using listener_type = SOCKET;

    //! Maximum size of address data in bytes.
    constexpr static const unsigned int MAX_ADDRESS_SIZE = 16;

    //! Destructor
    virtual ~CNetBackend() {}

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
};

#endif
