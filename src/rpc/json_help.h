// Copyright (c) 2025-2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_JSON_HELP_H
#define BITCOIN_RPC_JSON_HELP_H

#include <string>

struct RPCResult;

/** Return a commonly used RPCResult by field name, optionally overriding its
 *  optional flag and key name. Throws for an unknown key. */
RPCResult GetRpcResult(const std::string& key, bool optional = false, const std::string& override_name = "");

#endif // BITCOIN_RPC_JSON_HELP_H
