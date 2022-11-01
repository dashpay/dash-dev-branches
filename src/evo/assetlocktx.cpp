// Copyright (c) 2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/assetlocktx.h>
#include <evo/specialtx.h>

#include <consensus/params.h>

#include <chainparams.h>
#include <validation.h>

#include <llmq/signing.h>
#include <llmq/utils.h>
#include <llmq/quorums.h>

/*
   Common code for Asset Lock and Asset Unlock
    */
maybe_error CheckAssetLockUnlockTx(const CTransaction& tx, const CBlockIndex* pindexPrev)
{
    switch (tx.nType) {
    case TRANSACTION_ASSET_LOCK:
        return CheckAssetLockTx(tx);
    case TRANSACTION_ASSET_UNLOCK:
        return CheckAssetUnlockTx(tx, pindexPrev);
    default:
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-not-asset-locks-at-all"};
    }
}

/*
   Asset Lock Transaction
   */
maybe_error CheckAssetLockTx(const CTransaction& tx)
{
    if (tx.nType != TRANSACTION_ASSET_LOCK) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-type"};
    }

    CAmount returnAmount{0};
    for (const CTxOut& txout : tx.vout) {
        const CScript& script = txout.scriptPubKey;
        if (script.empty() || script[0] != OP_RETURN) continue;

        if (script.size() != 2 || script[1] != 0) return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-non-empty-return"};

        if (txout.nValue <= 0) return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-zeroout-return"};

        // Should be only one OP_RETURN
        if (returnAmount) return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-multiple-return"};
        returnAmount = txout.nValue;
    }

    if (returnAmount == 0) return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-no-return"};

    CAssetLockPayload assetLockTx;
    if (!GetTxPayload(tx, assetLockTx)) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-payload"};
    }

    if (assetLockTx.getVersion() == 0 || assetLockTx.getVersion() > CAssetLockPayload::CURRENT_VERSION) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-version"};
    }

    if (assetLockTx.getType() != 0) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-locktype"};
    }

    if (assetLockTx.getCreditOutputs().empty()) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-emptycreditoutputs"};
    }

    CAmount creditOutputsAmount = 0;
    for (const CTxOut& out : assetLockTx.getCreditOutputs()) {
        creditOutputsAmount += out.nValue;
        if (!out.scriptPubKey.IsPayToPublicKeyHash()) {
            return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-pubKeyHash"};
        }
    }
    if (creditOutputsAmount != returnAmount) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetlocktx-creditamount"};
    }

    return {};
}
std::string CAssetLockPayload::ToString() const
{
    std::string outputs{"["};
    for (const CTxOut& tx: creditOutputs) {
        outputs.append(tx.ToString());
        outputs.append(",");
    }
    outputs.back() = ']';
    return strprintf("CAssetLockPayload(nVersion=%d,nType=%d,creditOutputs=%s)", nVersion, nType, outputs.c_str());
}

uint16_t CAssetLockPayload::getVersion() const {
    return nVersion;
}

uint16_t CAssetLockPayload::getType() const {
    return nType;
}

const std::vector<CTxOut>& CAssetLockPayload::getCreditOutputs() const {
    return creditOutputs;
}

/*
   Asset Unlock Transaction (withdrawals)
   */
maybe_error CAssetUnlockPayload::VerifySig(const uint256& msgHash, int height) const
{
    Consensus::LLMQType llmqType = Params().GetConsensus().llmqTypeAssetLocks;

    const auto& llmq_params_opt = llmq::GetLLMQParams(llmqType);
    if (!llmq_params_opt) {
        return {ValidationInvalidReason::CONSENSUS, "bad-assetunlock-llmq-type"};
    }

    if (height < requestedHeight || height >= getHeightToExpiry()) {
        LogPrintf("Asset unlock tx %d with requested height %d could not be accepted on height: %d\n",
                index, requestedHeight, height);
        return {ValidationInvalidReason::CONSENSUS, "bad-assetunlock-too-late"};
    }

    const std::string id(strprintf("plwdtx%lld", index));

    std::vector<uint8_t> vchHash(32);
    CSHA256().Write(reinterpret_cast<const uint8_t*>(id.data()), id.size()).Finalize(vchHash.data());
    uint256 requestId(vchHash);

    // We check only current quorum and previous one, not further
    int signOffset{llmq::GetLLMQParams(llmqType).dkgInterval};
    for (int signIter = 0; signIter < 2; ++signIter) {
        if (llmq::CSigningManager::VerifyRecoveredSig(llmqType, *llmq::quorumManager, getRequestedHeight(), requestId, msgHash, quorumSig, signIter * signOffset)) {
            return {};
        }
    }

    return {ValidationInvalidReason::CONSENSUS, "bad-assetunlock-not-verified"};
}

maybe_error CheckAssetUnlockTx(const CTransaction& tx, const CBlockIndex* pindexPrev)
{
    if (tx.nType != TRANSACTION_ASSET_UNLOCK) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetunlocktx-type"};
    }

    if (!tx.vin.empty()) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetunlocktx-have-input"};
    }

    if (tx.vout.size() > CAssetUnlockPayload::MAXIMUM_WITHDRAWALS) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetunlocktx-too-many-outs"};
    }

    CAssetUnlockPayload assetUnlockTx;
    if (!GetTxPayload(tx, assetUnlockTx)) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetunlocktx-payload"};
    }

    if (assetUnlockTx.getVersion() == 0 || assetUnlockTx.getVersion() > CAssetUnlockPayload::CURRENT_VERSION) {
        return {ValidationInvalidReason::TX_BAD_SPECIAL, "bad-assetunlocktx-version"};
    }

    if (creditPool.indexes.contains(assetUnlockTx.getIndex())) {
        return {ValidationInvalidReason::CONSENSUS, "bad-assetunlock-duplicated-index"};
    }

    const CBlockIndex* pindexQuorum = WITH_LOCK(cs_main, return g_chainman.m_blockman.LookupBlockIndex(assetUnlockTx.getQuorumHash()));
    if (!pindexQuorum) {
        return {ValidationInvalidReason::CONSENSUS, "bad-assetunlock-quorum-hash"};
    }
    if (pindexQuorum != pindexPrev->GetAncestor(pindexQuorum->nHeight)) {
        // not part of active chain
        return {ValidationInvalidReason::CONSENSUS, "bad-assetunlock-quorum-hash-q"};
    }


    // Copy transaction except `quorumSig` field to calculate hash
    CMutableTransaction tx_copy(tx);
    auto payload_copy = CAssetUnlockPayload(assetUnlockTx.getVersion(), assetUnlockTx.getIndex(), assetUnlockTx.getFee(), assetUnlockTx.getRequestedHeight(), assetUnlockTx.getQuorumHash(), CBLSSignature());
    SetTxPayload(tx_copy, payload_copy);

    uint256 msgHash = tx_copy.GetHash();
    return assetUnlockTx.VerifySig(msgHash, pindexPrev->nHeight);
}

std::string CAssetUnlockPayload::ToString() const
{
    return strprintf("CAssetUnlockPayload(nVersion=%d,index=%d,fee=%d.%08d,requestedHeight=%d,quorumHash=%d,quorumSig=%s",
            nVersion, index, fee / COIN, fee % COIN, requestedHeight, quorumHash.GetHex(), quorumSig.ToString().c_str());
}

uint16_t CAssetUnlockPayload::getVersion() const {
    return nVersion;
}

uint64_t CAssetUnlockPayload::getIndex() const {
    return index;
}

uint32_t CAssetUnlockPayload::getFee() const {
    return fee;
}

uint32_t CAssetUnlockPayload::getRequestedHeight() const {
    return requestedHeight;
}

const uint256& CAssetUnlockPayload::getQuorumHash() const {
    return quorumHash;
}

const CBLSSignature& CAssetUnlockPayload::getQuorumSig() const {
    return quorumSig;
}

int CAssetUnlockPayload::getHeightToExpiry() const {
    Consensus::LLMQType llmqType = Params().GetConsensus().llmqTypeAssetLocks;

    assert(Params().HasLLMQ(llmqType));

    int signOffset{llmq::GetLLMQParams(llmqType).dkgInterval};
    // round up withing current and next quorum
    return requestedHeight + 2 * signOffset - requestedHeight % signOffset - 1;
}
