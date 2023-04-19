// Copyright (c) 2017-2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_CBTX_H
#define BITCOIN_EVO_CBTX_H

#include <bls/bls.h>
#include <primitives/transaction.h>
#include <univalue.h>

class BlockValidationState;
class CBlock;
class CBlockIndex;
class CCoinsViewCache;
class TxValidationState;

namespace llmq {
class CQuorumBlockProcessor;
class CChainLocksHandler;
}// namespace llmq

// coinbase transaction
class CCbTx
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_COINBASE;
    static constexpr uint16_t CB_V19_VERSION = 2;
    static constexpr uint16_t CB_CL_SIG_VERSION = 3;

    uint16_t nVersion{CB_V19_VERSION};
    int32_t nHeight{0};
    uint256 merkleRootMNList;
    uint256 merkleRootQuorums;
    uint32_t bestCLHeightDiff;
    CBLSSignature bestCLSignature;

    SERIALIZE_METHODS(CCbTx, obj)
    {
        READWRITE(obj.nVersion, obj.nHeight, obj.merkleRootMNList);

        if (obj.nVersion >= 2) {
            READWRITE(obj.merkleRootQuorums);
            if (obj.nVersion >= CB_CL_SIG_VERSION) {
                READWRITE(COMPACTSIZE(obj.bestCLHeightDiff));
                READWRITE(obj.bestCLSignature);
            }
        }
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", (int)nVersion);
        obj.pushKV("height", nHeight);
        obj.pushKV("merkleRootMNList", merkleRootMNList.ToString());
        if (nVersion >= 2) {
            obj.pushKV("merkleRootQuorums", merkleRootQuorums.ToString());
            if (nVersion >= CB_CL_SIG_VERSION) {
                obj.pushKV("bestCLHeightDiff", static_cast<int>(bestCLHeightDiff));
                obj.pushKV("bestCLSignature", bestCLSignature.ToString());
            }
        }
    }
};

bool CheckCbTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state);

bool CheckCbTxMerkleRoots(const CBlock& block, const CBlockIndex* pindex, const llmq::CQuorumBlockProcessor& quorum_block_processor, BlockValidationState& state, const CCoinsViewCache& view);
bool CalcCbTxMerkleRootMNList(const CBlock& block, const CBlockIndex* pindexPrev, uint256& merkleRootRet, BlockValidationState& state, const CCoinsViewCache& view);
bool CalcCbTxMerkleRootQuorums(const CBlock& block, const CBlockIndex* pindexPrev, const llmq::CQuorumBlockProcessor& quorum_block_processor, uint256& merkleRootRet, BlockValidationState& state);
bool CheckCbTxBestChainlock(const CBlock& block, const CBlockIndex* pindexPrev, const llmq::CChainLocksHandler& chainlock_handler, BlockValidationState& state);

bool EmplaceBestChainlock(const llmq::CChainLocksHandler& chainlock_handler, const int nHeight, uint32_t& bestCLHeightDiff, CBLSSignature& bestCLSignature);

#endif // BITCOIN_EVO_CBTX_H
