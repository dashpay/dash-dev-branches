// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "messagesigner.h"
#include "users.h"
#include "user.h"
#include "subtx.h"
#include "txmempool.h"
#include "script/standard.h"
#include "consensus/validation.h"
#include "specialtx.h"
#include "util.h"

CEvoUserManager *evoUserManager;

CEvoUserManager::CEvoUserManager(CEvoDB& _evoDb)
        : userDb(_evoDb)
{
}

static CAmount GetTxBurnAmount(const CTransaction& tx)
{
    CAmount burned = 0;
    for (auto& txo : tx.vout) {
        txnouttype type;
        std::vector<std::vector<unsigned char> > solutions;
        if (Solver(txo.scriptPubKey, type, solutions)) {
            if (type == TX_NULL_DATA) {
                burned += txo.nValue;
            }
        }
    }
    return burned;
}

bool CEvoUserManager::CheckSubTxRegister(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    LOCK(cs);

    CSubTxRegister subTx;
    if (!GetTxPayload(tx, subTx)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-payload");
    }
    if (subTx.nVersion != CSubTxRegister::CURRENT_VERSION) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-version");
    }

    if (userDb.UserNameExists(subTx.userName)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-dupusername");
    }

    CAmount topupAmount = GetTxBurnAmount(tx);

    if (topupAmount < MIN_SUBTX_TOPUP) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-lowtopup");
    }

    std::string verifyError;
    if (!CHashSigner::VerifyHash(subTx.GetSignHash(), subTx.pubKeyID, subTx.vchSig, verifyError)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-sig", false, verifyError);
    }

    // TODO check username validity

    return true;
}

bool CEvoUserManager::ProcessSubTxRegister(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees)
{
    LOCK(cs);

    CSubTxRegister subTx;
    if (!GetTxPayload(tx, subTx)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-payload");
    }

    CAmount topupAmount = GetTxBurnAmount(tx);

    CEvoUser user(tx.GetHash(), subTx.userName, subTx.pubKeyID);
    user.AddTopUp(topupAmount);
    userDb.PushSubTx(tx.GetHash(), tx.GetHash());
    userDb.PushPubKey(tx.GetHash(), subTx.pubKeyID);
    userDb.WriteUser(user);
    userDb.WriteUnspentSubTx(tx.GetHash(), tx.GetHash());

    return true;
}

bool CEvoUserManager::UndoSubTxRegister(const CTransaction &tx, const CBlockIndex* pindex)
{
    LOCK(cs);

    CSubTxRegister subTx;
    if (!GetTxPayload(tx, subTx)) {
        return error("CEvoUserManager::%s -- invalid subtx payload", __func__);
    }

    uint256 oldTopSubTx, newTopSubTx;
    if (!userDb.PopSubTx(tx.GetHash(), oldTopSubTx, newTopSubTx) || oldTopSubTx != tx.GetHash()) {
        return error("CEvoUserManager::%s -- unexpected subTx popped. expected %s, popped %s", __func__, tx.GetHash().ToString(), oldTopSubTx.ToString());
    }
    userDb.DeleteUser(tx.GetHash());
    userDb.DeleteUnspentSubTx(tx.GetHash(), tx.GetHash());
    return true;
}

template<class SubTx>
static bool GetSubTxAndUser(CEvoUserDb& userDb, const CTransaction& tx, SubTx& subTxRet, CEvoUser& userRet, bool includeMempool, CValidationState& state, bool allowClosed = false)
{
    if (!GetTxPayload(tx, subTxRet)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-payload");
    }
    if (subTxRet.nVersion != SubTx::CURRENT_VERSION) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-version");
    }

    bool userValid = false;
    if (userDb.GetUser(subTxRet.regTxId, userRet)) {
        userValid = true;
    } else if (includeMempool && evoUserManager->BuildUserFromMempool(subTxRet.regTxId, userRet)) {
        userValid = true;
    }
    if (!userValid) {
        // Low DoS score as peers may not know about this user yet
        return state.DoS(10, false, REJECT_TS_NOUSER, "bad-subtx-nouser");
    }

    if (includeMempool) {
        evoUserManager->TopupUserFromMempool(userRet);
        evoUserManager->ApplyUserSubTxsFromMempool(userRet, tx.GetHash());
    }

    if (!allowClosed && userRet.IsClosed()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-accountclosed");
    }
    return true;
}

template<class SubTx>
static bool CheckSubTxForUser(CEvoUserDb& userDb, const CTransaction& tx, SubTx& subTxRet, CEvoUser& userRet, bool includeMempool, CValidationState& state)
{
    if (!GetSubTxAndUser(userDb, tx, subTxRet, userRet, includeMempool, state)) {
        return false;
    }

    if (subTxRet.hashPrevSubTx != userRet.GetCurSubTx()) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-ancenstor");
    }
    if (userDb.HasUnspentSubTx(subTxRet.regTxId, subTxRet.hashPrevSubTx)) {
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-ancenstor");
    }

    std::string strError;
    if (!CHashSigner::VerifyHash(subTxRet.GetSignHash(), userRet.GetCurPubKeyID(), subTxRet.vchSig, strError)) {
        // TODO immediately ban?
        return state.DoS(10, false, REJECT_INVALID, "bad-subtx-sig");
    }

    return true;
}

template<class SubTx>
static bool CheckSubTxAndFeeForUser(CEvoUserDb& userDb,const CTransaction& tx, SubTx& subTxRet, CEvoUser& userRet, bool includeMempool, CValidationState& state)
{
    if (!CheckSubTxForUser(userDb, tx, subTxRet, userRet, includeMempool, state)) {
        return false;
    }

    // TODO min fee depending on TS size
    if (subTxRet.creditFee < EVO_TS_MIN_FEE || subTxRet.creditFee > EVO_TS_MAX_FEE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-fee");
    }

    if (userRet.GetCreditBalance() < subTxRet.creditFee) {
        // Low DoS score as peers may not know about the low balance (e.g. due to not mined topups)
        return state.DoS(10, false, REJECT_INSUFFICIENTFEE, "bad-subtx-nocredits");
    }
    return true;
}

bool CEvoUserManager::CheckSubTxTopup(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    LOCK(cs);

    CSubTxTopup subTx;
    CEvoUser user;
    if (!GetSubTxAndUser(userDb, tx, subTx, user, false, state)) {
        return false;
    }

    CAmount topupAmount = GetTxBurnAmount(tx);
    if (topupAmount < MIN_SUBTX_TOPUP) {
        return state.DoS(100, false, REJECT_INVALID, "bad-subtx-lowtopup");
    }

    return true;
}

bool CEvoUserManager::ProcessSubTxTopup(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees)
{
    LOCK(cs);

    CSubTxTopup subTx;
    CEvoUser user;
    if (!GetSubTxAndUser(userDb, tx, subTx, user, false, state)) {
        return false;
    }

    CAmount topupAmount = GetTxBurnAmount(tx);
    user.AddTopUp(topupAmount);
    // We don't push the subTx hash here as everyone can topup a users credits and the order is also not important
    userDb.WriteUser(user);
    return true;
}

bool CEvoUserManager::UndoSubTxTopup(const CTransaction &tx, const CBlockIndex* pindex)
{
    LOCK(cs);

    CSubTxTopup subTx;
    CEvoUser user;
    CValidationState dummyState;
    if (!GetSubTxAndUser(userDb, tx, subTx, user, false, dummyState)) {
        return false;
    }

    CAmount topupAmount = GetTxBurnAmount(tx);
    user.AddTopUp(-topupAmount);
    userDb.WriteUser(user);
    return true;
}

bool CEvoUserManager::CheckSubTxResetKey(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    LOCK(cs);

    CSubTxResetKey subTx;
    CEvoUser user;
    if (!CheckSubTxAndFeeForUser(userDb, tx, subTx, user, false, state)) {
        return false;
    }
    return true;
}

bool CEvoUserManager::ProcessSubTxResetKey(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees)
{
    LOCK(cs);

    CSubTxResetKey subTx;
    CEvoUser user;
    if (!GetSubTxAndUser(userDb, tx, subTx, user, false, state)) {
        return false;
    }

    user.SetCurSubTx(tx.GetHash());
    user.SetCurPubKeyID(subTx.newPubKeyId);
    user.AddSpend(subTx.creditFee);
    specialTxFees += subTx.creditFee;
    userDb.WriteUser(user);

    userDb.PushSubTx(subTx.regTxId, tx.GetHash());
    userDb.PushPubKey(subTx.regTxId, subTx.newPubKeyId);
    userDb.DeleteUnspentSubTx(subTx.regTxId, subTx.hashPrevSubTx);
    userDb.WriteUnspentSubTx(subTx.regTxId, tx.GetHash());

    return true;
}

bool CEvoUserManager::UndoSubTxResetKey(const CTransaction &tx, const CBlockIndex* pindex)
{
    LOCK(cs);

    CSubTxResetKey subTx;
    CEvoUser user;
    CValidationState dummyState;
    if (!GetSubTxAndUser(userDb, tx, subTx, user, false, dummyState)) {
        return false;
    }

    uint256 oldTopSubTx, newTopSubTx;
    if (!userDb.PopSubTx(subTx.regTxId, oldTopSubTx, newTopSubTx) || oldTopSubTx != tx.GetHash()) {
        return error("CEvoUserManager::%s -- unexpected subTx popped. expected %s, popped %s", __func__, tx.GetHash().ToString(), oldTopSubTx.ToString());
    }

    CKeyID oldTop, newTop;
    userDb.PopPubKey(subTx.regTxId, oldTop, newTop);
    if (oldTop != subTx.newPubKeyId || newTop.IsNull()) {
        return error("CEvoUserManager::%s -- unexpected key %s popped from user %s. Expected %s",
                     __func__, oldTop.ToString(), user.GetRegTxId().ToString(), subTx.newPubKeyId.ToString());
    }
    user.SetCurSubTx(subTx.hashPrevSubTx);
    user.SetCurPubKeyID(newTop);
    user.AddSpend(-subTx.creditFee);
    userDb.WriteUser(user);
    userDb.DeleteUnspentSubTx(subTx.regTxId, tx.GetHash());
    userDb.WriteUnspentSubTx(subTx.regTxId, subTx.hashPrevSubTx);
    return true;
}

bool CEvoUserManager::CheckSubTxCloseAccount(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    LOCK(cs);

    CSubTxResetKey subTx;
    CEvoUser user;
    if (!CheckSubTxAndFeeForUser(userDb, tx, subTx, user, false, state)) {
        return false;
    }
    return true;
}

bool CEvoUserManager::ProcessSubTxCloseAccount(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees)
{
    LOCK(cs);

    CSubTxCloseAccount subTx;
    CEvoUser user;
    if (!GetSubTxAndUser(userDb, tx, subTx, user, false, state)) {
        return false;
    }
    user.SetCurSubTx(tx.GetHash());
    user.AddSpend(subTx.creditFee);
    specialTxFees += subTx.creditFee;
    user.SetClosed(true);
    userDb.WriteUser(user);
    userDb.PushSubTx(subTx.regTxId, tx.GetHash());
    userDb.DeleteUnspentSubTx(subTx.regTxId, subTx.hashPrevSubTx);
    userDb.WriteUnspentSubTx(subTx.regTxId, tx.GetHash());
    return true;
}

bool CEvoUserManager::UndoSubTxCloseAccount(const CTransaction &tx, const CBlockIndex* pindex)
{
    LOCK(cs);

    CSubTxCloseAccount subTx;
    CEvoUser user;
    CValidationState dummyState;
    if (!GetSubTxAndUser(userDb, tx, subTx, user, false, dummyState, true)) {
        return false;
    }
    user.SetCurSubTx(subTx.hashPrevSubTx);
    user.SetClosed(false);
    user.AddSpend(-subTx.creditFee);

    uint256 oldTopSubTx, newTopSubTx;
    if (!userDb.PopSubTx(subTx.regTxId, oldTopSubTx, newTopSubTx) || oldTopSubTx != tx.GetHash()) {
        return error("CEvoUserManager::%s -- unexpected subTx popped. expected %s, popped %s", __func__, tx.GetHash().ToString(), oldTopSubTx.ToString());
    }

    userDb.WriteUser(user);
    userDb.DeleteUnspentSubTx(subTx.regTxId, tx.GetHash());
    userDb.WriteUnspentSubTx(subTx.regTxId, subTx.hashPrevSubTx);
    return true;
}


bool CEvoUserManager::CheckSubTxTransition(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state)
{
    LOCK(cs);

    CSubTxTransition subTx;
    CEvoUser user;
    if (!CheckSubTxAndFeeForUser(userDb, tx, subTx, user, false, state)) {
        return false;
    }
    if (subTx.hashPrevSubTx != user.GetCurSubTx()) {
        return state.DoS(10, false, REJECT_TS_ANCESTOR, "bad-subtx-ts-ancestor");
    }
    return true;
}

bool CEvoUserManager::ProcessSubTxTransition(const CTransaction &tx, const CBlockIndex* pindex, CValidationState& state, CAmount& specialTxFees)
{
    LOCK(cs);

    CSubTxTransition subTx;
    CEvoUser user;
    if (!GetSubTxAndUser(userDb, tx, subTx, user, false, state)) {
        return false;
    }

    user.SetCurSubTx(tx.GetHash());
    user.SetCurHashSTPacket(subTx.hashSTPacket);
    user.AddSpend(subTx.creditFee);
    specialTxFees += subTx.creditFee;
    userDb.WriteUser(user);
    userDb.PushSubTx(subTx.regTxId, tx.GetHash());
    userDb.PushHashSTPacket(subTx.regTxId, subTx.hashSTPacket);
    userDb.DeleteUnspentSubTx(subTx.regTxId, subTx.hashPrevSubTx);
    userDb.WriteUnspentSubTx(subTx.regTxId, tx.GetHash());
    return true;
}

bool CEvoUserManager::UndoSubTxTransition(const CTransaction &tx, const CBlockIndex* pindex)
{
    LOCK(cs);

    CSubTxTransition subTx;
    CEvoUser user;
    CValidationState dummyState;
    if (!GetSubTxAndUser(userDb, tx, subTx, user, false, dummyState)) {
        return false;
    }

    uint256 oldTopSubTx, newTopSubTx;
    if (!userDb.PopSubTx(subTx.regTxId, oldTopSubTx, newTopSubTx) || oldTopSubTx != tx.GetHash()) {
        return error("CEvoUserManager::%s -- unexpected subTx popped. expected %s, popped %s", __func__, tx.GetHash().ToString(), oldTopSubTx.ToString());
    }

    uint256 oldTop, newTop;
    userDb.PopHashSTPacket(subTx.regTxId, oldTop, newTop);
    if (oldTop != subTx.hashSTPacket) {
        return error("CEvoUserManager::%s -- popped hashSTPacket %s for user %s. Expected %s",
                     __func__, oldTop.ToString(), user.GetRegTxId().ToString(), subTx.hashSTPacket.ToString());
    }
    user.SetCurSubTx(subTx.hashPrevSubTx);
    user.SetCurHashSTPacket(newTop);
    user.AddSpend(-subTx.creditFee);
    userDb.WriteUser(user);
    userDb.DeleteUnspentSubTx(subTx.regTxId, tx.GetHash());
    userDb.WriteUnspentSubTx(subTx.regTxId, subTx.hashPrevSubTx);
    return true;
}

bool CEvoUserManager::BuildUserFromMempool(const uint256& regTxId, CEvoUser& user)
{
    auto tx = mempool.get(regTxId);
    if (tx == nullptr) {
        return false;
    }

    CValidationState dummyState;
    if (!CheckSubTxRegister(*tx, nullptr, dummyState)) {
        return false;
    }

    CSubTxRegister subTx;
    GetTxPayloadAssert(*tx, subTx);

    user = CEvoUser(regTxId, subTx.userName, subTx.pubKeyID);
    user.AddTopUp(GetTxBurnAmount(*tx));

    return true;
}

bool CEvoUserManager::TopupUserFromMempool(CEvoUser& user)
{
    std::vector<CTransactionRef> topups;
    if (!mempool.getTopupsForUser(user.GetRegTxId(), topups))
        return false;

    bool didTopup = false;
    for (const auto &tx : topups) {
        CValidationState dummyState;
        if (!CheckSubTxTopup(*tx, nullptr, dummyState)) {
            continue;
        }
        CAmount topupAmount = GetTxBurnAmount(*tx);
        user.AddTopUp(topupAmount);
        didTopup = true;
    }
    return didTopup;
}

bool CEvoUserManager::ApplyUserSubTxsFromMempool(CEvoUser& user, const uint256& stopAtSubTx)
{
    // TODO
    return true;
}

bool CEvoUserManager::GetUser(const uint256& regTxId, CEvoUser& user)
{
    LOCK(cs);
    return userDb.GetUser(regTxId, user);
}

bool CEvoUserManager::GetUserIdByName(const std::string& userName, uint256& regTxIdRet)
{
    LOCK(cs);
    return userDb.GetUserIdByName(userName, regTxIdRet);
}

std::vector<uint256> CEvoUserManager::ListUserSubTxs(const uint256& regTxId)
{
    LOCK(cs);
    return userDb.ListUserSubTxs(regTxId);
}
