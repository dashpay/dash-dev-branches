// Copyright (c) 2024 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INTERFACES_COINJOIN_H
#define BITCOIN_INTERFACES_COINJOIN_H

#include <memory>
#include <string>

class CoinJoinWalletManager;
class CWallet;

namespace interfaces {
namespace CoinJoin {
//! Interface for the wallet constrained src/coinjoin part of a dash node (dashd process).
class Client
{
public:
    virtual ~Client() {}
    virtual void resetCachedBlocks() = 0;
    virtual void resetPool() = 0;
    virtual int getCachedBlocks() = 0;
    virtual std::string getSessionDenoms() = 0;
    virtual void setCachedBlocks(int nCachedBlocks) = 0;
    virtual void disableAutobackups() = 0;
    virtual bool isMixing() = 0;
    virtual bool startMixing() = 0;
    virtual void stopMixing() = 0;
};
class Loader
{
public:
    virtual ~Loader() {}
    //! Add new wallet to CoinJoin client manager
    virtual void AddWallet(CWallet&) = 0;
    //! Remove wallet from CoinJoin client manager
    virtual void RemoveWallet(const std::string&) = 0;
    virtual void FlushWallet(const std::string&) = 0;
    virtual std::unique_ptr<CoinJoin::Client> GetClient(const std::string&) = 0;
};
} // namespace CoinJoin

std::unique_ptr<CoinJoin::Client> MakeCoinJoinClient(const CoinJoinWalletManager& walletman, const std::string& name);
std::unique_ptr<CoinJoin::Loader> MakeCoinJoinLoader(CoinJoinWalletManager& walletman);

} // namespace interfaces

#endif // BITCOIN_INTERFACES_COINJOIN_H
