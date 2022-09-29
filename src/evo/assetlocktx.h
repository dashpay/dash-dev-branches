// Copyright (c) 2023 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_ASSETLOCKTX_H
#define BITCOIN_EVO_ASSETLOCKTX_H

#include <bls/bls_ies.h>
#include <evo/specialtx.h>
#include <primitives/transaction.h>

#include <key_io.h>
#include <serialize.h>
#include <tinyformat.h>
#include <univalue.h>

class CBlockIndex;

class CAssetLockPayload
{
public:
    static constexpr uint16_t CURRENT_VERSION = 1;
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_ASSET_LOCK;

private:
    uint16_t nVersion{CURRENT_VERSION};
    uint16_t nType{0};
    std::vector<CTxOut> creditOutputs;

public:
    CAssetLockPayload(uint16_t nType, const std::vector<CTxOut>& creditOutputs) :
        nType(nType),
        creditOutputs(creditOutputs)
    {}

    CAssetLockPayload() = default;

    SERIALIZE_METHODS(CAssetLockPayload, obj)
    {
        READWRITE(
            obj.nVersion,
            obj.nType,
            obj.creditOutputs
        );
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", int(nVersion));
        obj.pushKV("type", int(nType));
        UniValue outputs;
        outputs.setArray();
        for (const CTxOut& out : creditOutputs) {
            outputs.push_back(out.ToString());
        }
        obj.pushKV("creditOutputs", outputs);
    }

    // getters
    uint16_t getVersion() const;
    uint16_t getType() const;
    const std::vector<CTxOut>& getCreditOutputs() const;
};

class CAssetUnlockPayload
{
public:
    static constexpr uint16_t CURRENT_VERSION = 1;
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_ASSET_UNLOCK;

    static constexpr size_t MAXIMUM_WITHDRAWALS = 32;

private:
    uint16_t nVersion{CURRENT_VERSION};
    uint64_t index{0};
    uint32_t fee{0};
    uint32_t requestedHeight{0};
    uint256 quorumHash{0};
    CBLSSignature quorumSig{};

public:
    CAssetUnlockPayload(uint16_t nVersion, uint64_t index, uint32_t fee, uint32_t requestedHeight,
            uint256 quorumHash, CBLSSignature quorumSig) :
        nVersion(nVersion),
        index(index),
        fee(fee),
        requestedHeight(requestedHeight),
        quorumHash(quorumHash),
        quorumSig(quorumSig)
    {}

    CAssetUnlockPayload() = default;

    SERIALIZE_METHODS(CAssetUnlockPayload, obj)
    {
        READWRITE(
            obj.nVersion,
            obj.index,
            obj.fee,
            obj.requestedHeight,
            obj.quorumHash,
            obj.quorumSig
        );
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", int(nVersion));
        obj.pushKV("index", int(index));
        obj.pushKV("fee", int(fee));
        obj.pushKV("requestedHeight", int(requestedHeight));
        obj.pushKV("quorumHash", quorumHash.ToString());
        obj.pushKV("quorumSig", quorumSig.ToString());
    }

    bool VerifySig(const uint256& msgHash, const CBlockIndex* pindexTip, TxValidationState& state) const;

    // getters
    uint16_t getVersion() const;
    uint16_t getType() const;
    uint64_t getIndex() const;
    uint32_t getFee() const;
    uint32_t getRequestedHeight() const;
    const uint256& getQuorumHash() const;
    const CBLSSignature& getQuorumSig() const;

    // used by mempool to know when possible to drop a transaction as expired
    int getHeightToExpiry() const;
};

bool CheckAssetLockTx(const CTransaction& tx, TxValidationState& state);
bool CheckAssetUnlockTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state);
bool CheckAssetLockUnlockTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state);

#endif // BITCOIN_EVO_ASSETLOCKTX_H
