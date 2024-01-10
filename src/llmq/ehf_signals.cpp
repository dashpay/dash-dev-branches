// Copyright (c) 2023 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/ehf_signals.h>
#include <llmq/quorums.h>
#include <llmq/signing_shares.h>
#include <llmq/commitment.h>

#include <evo/mnhftx.h>
#include <evo/specialtx.h>

#include <chainparams.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <index/txindex.h> // g_txindex
#include <primitives/transaction.h>
#include <spork.h>
#include <txmempool.h>
#include <validation.h>

namespace llmq {


CEHFSignalsHandler::CEHFSignalsHandler(CChainState& chainstate, CConnman& connman,
                                       CSigningManager& sigman, CSigSharesManager& shareman,
                                       const CSporkManager& sporkman, const CQuorumManager& qman, CTxMemPool& mempool) :
    chainstate(chainstate),
    connman(connman),
    sigman(sigman),
    shareman(shareman),
    sporkman(sporkman),
    qman(qman),
    mempool(mempool)
{
    sigman.RegisterRecoveredSigsListener(this);
}


CEHFSignalsHandler::~CEHFSignalsHandler()
{
    sigman.UnregisterRecoveredSigsListener(this);
}

void CEHFSignalsHandler::UpdatedBlockTip(const CBlockIndex* const pindexNew)
{
    if (!DeploymentActiveAfter(pindexNew, Params().GetConsensus(), Consensus::DEPLOYMENT_V20)) return;

    if (!fMasternodeMode || (Params().IsTestChain() && !sporkman.IsSporkActive(SPORK_24_TEST_EHF))) {
        return;
    }

    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        // TODO: v20 will never attempt to create EHF messages on main net; if this is needed it will be done by v20.1 or v21 nodes
        return;
    }
    // TODO: should do this for all not-yet-signied bits
    trySignEHFSignal(Params().GetConsensus().vDeployments[Consensus::DEPLOYMENT_MN_RR].bit, pindexNew);
}

void CEHFSignalsHandler::trySignEHFSignal(int bit, const CBlockIndex* const pindex)
{
    MNHFTxPayload mnhfPayload;
    mnhfPayload.signal.versionBit = bit;
    const uint256 requestId = mnhfPayload.GetRequestId();

    const Consensus::LLMQType& llmqType = Params().GetConsensus().llmqTypeMnhf;
    const auto& llmq_params_opt = Params().GetLLMQ(llmqType);
    if (!llmq_params_opt.has_value()) {
        return;
    }
    if (sigman.HasRecoveredSigForId(llmqType, requestId)) {
        LOCK(cs);
        ids.insert(requestId);

        LogPrint(BCLog::EHF, "CEHFSignalsHandler::trySignEHFSignal: already signed bit=%d at height=%d id=%s\n", bit, pindex->nHeight, requestId.ToString());
        // no need to sign same message one more time
        return;
    }

    const auto quorum = sigman.SelectQuorumForSigning(llmq_params_opt.value(), qman, requestId);
    if (!quorum) {
        LogPrintf("CEHFSignalsHandler::trySignEHFSignal no quorum for id=%s\n", requestId.ToString());
        return;
    }

    LogPrint(BCLog::EHF, "CEHFSignalsHandler::trySignEHFSignal: bit=%d at height=%d id=%s\n", bit, pindex->nHeight, requestId.ToString());
    mnhfPayload.signal.quorumHash = quorum->qc->quorumHash;
    const uint256 msgHash = mnhfPayload.PrepareTx().GetHash();

    {
        LOCK(cs);
        ids.insert(requestId);
    }
    sigman.AsyncSignIfMember(llmqType, shareman, requestId, msgHash);
}

void CEHFSignalsHandler::HandleNewRecoveredSig(const CRecoveredSig& recoveredSig)
{
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        // TODO: v20 will never attempt to create EHF messages on main net; if this is needed it will be done by v20.1 or v21 nodes
        return;
    }
    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }

    if (WITH_LOCK(cs, return ids.find(recoveredSig.getId()) == ids.end())) {
        // Do nothing, it's not for this handler
        return;
    }

    MNHFTxPayload mnhfPayload;
    // TODO: should do this for all not-yet-signied bits
    mnhfPayload.signal.versionBit = Params().GetConsensus().vDeployments[Consensus::DEPLOYMENT_MN_RR].bit;

    const uint256 expectedId = mnhfPayload.GetRequestId();
    LogPrint(BCLog::EHF, "CEHFSignalsHandler::HandleNewRecoveredSig expecting ID=%s received=%s\n", expectedId.ToString(), recoveredSig.getId().ToString());
    if (recoveredSig.getId() != mnhfPayload.GetRequestId()) {
        // there's nothing interesting for CEHFSignalsHandler
        LogPrint(BCLog::EHF, "CEHFSignalsHandler::HandleNewRecoveredSig id is known but it's not MN_RR, expected: %s\n", mnhfPayload.GetRequestId().ToString());
        return;
    }

    mnhfPayload.signal.quorumHash = recoveredSig.getQuorumHash();
    mnhfPayload.signal.sig = recoveredSig.sig.Get();

    CMutableTransaction tx = mnhfPayload.PrepareTx();

    {
        CTransactionRef tx_to_sent = MakeTransactionRef(std::move(tx));
        LogPrintf("CEHFSignalsHandler::HandleNewRecoveredSig Special EHF TX is created hash=%s\n", tx_to_sent->GetHash().ToString());
        LOCK(cs_main);
        TxValidationState state;
        if (AcceptToMemoryPool(chainstate, mempool, state, tx_to_sent, /* bypass_limits=*/ false, /* nAbsurdFee=*/ 0)) {
            connman.RelayTransaction(*tx_to_sent);
        } else {
            LogPrintf("CEHFSignalsHandler::HandleNewRecoveredSig -- AcceptToMemoryPool failed: %s\n", state.ToString());
        }
    }
}
} // namespace llmq
