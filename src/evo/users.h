// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_EVO_USERS_H
#define DASH_EVO_USERS_H

#include "sync.h"
#include "pubkey.h"
#include "uint256.h"
#include "serialize.h"
#include "amount.h"

#include "usersdb.h"
#include "subtx.h"

class CTransaction;
class CBlockIndex;
class CValidationState;

class CSubTxTopup;
class CSubTxResetKey;
class CSubTxCloseAccount;
class CSubTxTransition;

class CEvoUserManager {
public:
    CCriticalSection cs;

private:
    CEvoUserDb userDb;

public:
    CEvoUserManager(CEvoDB& _evoDb);

    bool CheckSubTxRegister(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
    bool ProcessSubTxRegister(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees);
    bool UndoSubTxRegister(const CTransaction &tx, const CBlockIndex* pindex);

    bool CheckSubTxTopup(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
    bool ProcessSubTxTopupForUser(CEvoUser& user, const CTransaction &tx, const CSubTxTopup& subTx, CValidationState& state);
    bool ProcessSubTxTopup(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees);
    bool UndoSubTxTopup(const CTransaction &tx, const CBlockIndex* pindex);

    bool CheckSubTxResetKey(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
    bool ProcessSubTxResetKeyForUser(CEvoUser& user, const CTransaction &tx, const CSubTxResetKey& subTx, CValidationState& state);
    bool ProcessSubTxResetKey(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees);
    bool UndoSubTxResetKey(const CTransaction &tx, const CBlockIndex* pindex);

    bool CheckSubTxCloseAccount(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);
    bool ProcessSubTxCloseAccountForUser(CEvoUser& user, const CTransaction &tx, const CSubTxCloseAccount& subTx, CValidationState& state);
    bool ProcessSubTxCloseAccount(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees);
    bool UndoSubTxCloseAccount(const CTransaction &tx, const CBlockIndex* pindex);

    bool CheckSubTxTransition(const CTransaction& tx, const CBlockIndex* pindexPrev, bool forMempool, CValidationState& state);
    bool ProcessSubTxTransitionForUser(CEvoUser& user, const CTransaction &tx, const CSubTxTransition& subTx, CValidationState& state);
    bool ProcessSubTxTransition(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees);
    bool UndoSubTxTransition(const CTransaction &tx, const CBlockIndex* pindex);

    bool GetUser(const uint256& regTxId, CEvoUser& userRet, bool includeMempool, bool* fromMempool = nullptr);
    bool GetUserIdByName(const std::string& userName, uint256& regTxIdRet);
    std::vector<uint256> ListUserSubTxs(const uint256& regTxId);

public:
    bool BuildUserFromMempool(const uint256& regTxId, CEvoUser& user);
    bool ApplyUserSubTxsFromMempool(CEvoUser& user, const uint256& stopAtSubTx = uint256());
};

extern CEvoUserManager *evoUserManager;

#endif //DASH_EVO_USERS_H
