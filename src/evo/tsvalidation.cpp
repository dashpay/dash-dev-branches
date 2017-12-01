// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/validation.h"
#include "net.h"
#include "net_processing.h"
#include "tsvalidation.h"
#include "tsmempool.h"
#include "txmempool.h"

void RelayNowValidTransitions() {
    std::vector<uint256> validTsHashes;
    tsMempool.GetNowValidWaitForRelayTransitions(validTsHashes);

    for (const uint256 &tsHash : validTsHashes) {
        CInv inv(MSG_TRANSITION, tsHash);
        g_connman->RelayInv(inv, MIN_EVO_PROTO_VERSION);
    }

    tsMempool.RemoveWaitForRelay(validTsHashes);
}

void HandleIncomingTransition(CNode *pfrom, const CTransition &ts) {
    if (tsMempool.Exists(ts.GetHash()))
        return;

    // We always add the TS to the mempool no matter if they are valid or invalid
    // This is because a TS may be invalid when we first see it, but may get valid later when
    // other SubTxs or transitions get mined. We however do not relay invalid transitions at first
    // and give DoS score for these. When new SubTx or transitions are mined for this user, we try
    // to revalidate all TSs and might relay previously invalid transitions then
    tsMempool.AddTransition(ts);

    {
        LOCK(cs_main);
        CValidationState state;
        if (!CheckTransition(ts, true, true, state)) {
            int nDoS = 0;
            if (state.IsInvalid(nDoS)) {
                LogPrint("evo-ts", "transition %s from peer=%d not valid: %s\n", ts.GetHash().ToString(), pfrom->id, FormatStateMessage(state));
                if (state.GetRejectCode() < REJECT_INTERNAL) // Never send internal codes over P2P
                    g_connman->PushMessage(pfrom, NetMsgType::REJECT, std::string(NetMsgType::TRANSITION), (unsigned char)state.GetRejectCode(),
                                        state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), ts.GetHash());
                if (nDoS > 0)
                    Misbehaving(pfrom->GetId(), nDoS);

            } else {
                // should actually not happen
                LogPrint("evo-ts", "error while checking transition %s from peer=%d: %s\n", ts.GetHash().ToString(), pfrom->id, FormatStateMessage(state));
                return;
            }
            if (state.GetRejectCode() == REJECT_TS_ANCESTOR) {
                pfrom->AskFor(CInv(MSG_TRANSITION, ts.hashPrevTransition));
            } else if (state.GetRejectCode() == REJECT_TS_NOUSER) {
                pfrom->AskFor(CInv(MSG_TX, ts.hashRegTx));
                if (!ts.hashPrevTransition.IsNull())
                    pfrom->AskFor(CInv(MSG_TRANSITION, ts.hashPrevTransition));
            }

            // add to the waitForReleay set in case there is a chance for recovery when other TSs/SubTx arrive
            if (state.GetRejectCode() == REJECT_TS_ANCESTOR || state.GetRejectCode() == REJECT_TS_NOUSER || state.GetRejectCode() == REJECT_INSUFFICIENTFEE)
                tsMempool.AddWaitForRelay(ts.GetHash());
        } else {
            CInv inv(MSG_TRANSITION, ts.GetHash());
            g_connman->RelayInv(inv, MIN_EVO_PROTO_VERSION);
            RelayNowValidTransitions();
        }
    }
}



// this can be called multiple times for the same block. this is needed if new register SubTxs are later added to the block
void AddMempoolTransitionsToBlock(CBlock &block, uint64_t maxTsSpace, uint64_t maxBlockSize) {
    LOCK(tsMempool.cs);

    // TODO fee based selection for miner reward maximization

    std::vector<uint256> userRegTxs;
    if (!tsMempool.GetUsers(userRegTxs))
        return;

    std::map<uint256, CEvoUser> users;
    GetUsers(userRegTxs, users);

    // add transitions one at a time per user to evenly distribute block space
    // TODO: Change this to be fee based (without loosing correct order) as miners most likely wish to maximize profits.
    uint64_t tsSpaceUsed = ::GetSerializeSize(block.vts, SER_NETWORK, CLIENT_VERSION);
    uint64_t blockSize = block.GetSerializeSize(SER_NETWORK, CLIENT_VERSION);
    while (true) {
        bool stop = true;
        for (auto &p : users) {
            CEvoUser &user = p.second;

            CTransition ts;
            if (!tsMempool.GetNextTransitionForUser(user, ts))
                continue;

            uint64_t tsSize = ::GetSerializeSize(ts, SER_NETWORK, CLIENT_VERSION);
            if (tsSpaceUsed + tsSize > maxTsSpace || blockSize + tsSize > maxBlockSize)
                continue;

            CValidationState state;
            if (!CheckTransitionForUser(ts, user, true, state)) {
                LogPrintf("AddTransitionsToBlock(): CheckTransition failed for %s. state=%s\n", ts.GetHash().ToString(), FormatStateMessage(state));
                continue;
            }
            if (!ProcessTransitionForUser(ts, user, state)) {
                LogPrintf("AddTransitionsToBlock(): ProcessTransitionForUser failed for %s. state=%s\n", ts.GetHash().ToString(), FormatStateMessage(state));
                continue;
            }

            tsSpaceUsed += tsSize;
            blockSize += tsSize;
            block.vts.push_back(ts);
            stop = false;
        }
        if (stop)
            break;
    }
}

CAmount CalcTransitionFeesForBlock(const CBlock &block) {
    CAmount fees = 0;
    for (const CTransition &ts : block.vts) {
        fees += ts.nFee;
    }
    return fees;
}
