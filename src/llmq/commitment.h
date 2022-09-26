// Copyright (c) 2018-2022 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LLMQ_COMMITMENT_H
#define BITCOIN_LLMQ_COMMITMENT_H

#include <bls/bls.h>
#include <consensus/params.h>
#include <primitives/transaction.h>
#include <util/irange.h>
#include <util/strencodings.h>

#include <univalue.h>

class CBlockIndex;
class CValidationState;

namespace llmq
{

// This message is an aggregation of all received premature commitments and only valid if
// enough (>=threshold) premature commitments were aggregated
// This is mined on-chain as part of TRANSACTION_QUORUM_COMMITMENT
class CFinalCommitment
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_PROVIDER_REGISTER;

    static constexpr uint16_t LEGACY_BLS_NON_INDEXED_QUORUM_VERSION = 1;
    static constexpr uint16_t LEGACY_BLS_INDEXED_QUORUM_VERSION = 2;
    static constexpr uint16_t BASIC_BLS_NON_INDEXED_QUORUM_VERSION = 3;
    static constexpr uint16_t BASIC_BLS_INDEXED_QUORUM_VERSION = 4;

public:
    uint16_t nVersion{LEGACY_BLS_NON_INDEXED_QUORUM_VERSION};
    Consensus::LLMQType llmqType{Consensus::LLMQType::LLMQ_NONE};
    uint256 quorumHash;
    int16_t quorumIndex{0};
    std::vector<bool> signers;
    std::vector<bool> validMembers;

    CBLSPublicKey quorumPublicKey;
    uint256 quorumVvecHash;

    CBLSSignature quorumSig; // recovered threshold sig of blockHash+validMembers+pubKeyHash+vvecHash
    CBLSSignature membersSig; // aggregated member sig of blockHash+validMembers+pubKeyHash+vvecHash

public:
    CFinalCommitment() = default;
    CFinalCommitment(const Consensus::LLMQParams& params, const uint256& _quorumHash);

    int CountSigners() const
    {
        return int(std::count(signers.begin(), signers.end(), true));
    }
    int CountValidMembers() const
    {
        return int(std::count(validMembers.begin(), validMembers.end(), true));
    }

    bool Verify(const CBlockIndex* pQuorumBaseBlockIndex, bool checkSigs) const;
    bool VerifyNull() const;
    bool VerifySizes(const Consensus::LLMQParams& params) const;

public:
    template <typename Stream, typename Operation>
    inline void SerializationOpBase(Stream& s, Operation ser_action)
    {
        READWRITE(nVersion,
                  llmqType,
                  quorumHash
        );
    }

    template <typename Stream, typename Operation>
    inline void SerializationOpTail(Stream& s, Operation ser_action)
    {
        READWRITE(quorumVvecHash,
                  quorumSig,
                  membersSig);
    }

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        const_cast<CFinalCommitment*>(this)->SerializationOpBase(s, CSerActionSerialize());
        if (nVersion == LEGACY_BLS_INDEXED_QUORUM_VERSION || nVersion == BASIC_BLS_INDEXED_QUORUM_VERSION)
        {
            ser_writedata16(s, quorumIndex);
        }
        DynamicBitSetFormatter dyn_ser;
        dyn_ser.Ser(s, signers);
        dyn_ser.Ser(s, validMembers);
        bool fLegacyScheme = (nVersion == LEGACY_BLS_NON_INDEXED_QUORUM_VERSION || nVersion == LEGACY_BLS_INDEXED_QUORUM_VERSION);
        quorumPublicKey.Serialize(s, fLegacyScheme);
        const_cast<CFinalCommitment*>(this)->SerializationOpTail(s, CSerActionSerialize());
    }

    template <typename Stream>
    inline void Unserialize(Stream& s)
    {
        SerializationOpBase(s, CSerActionUnserialize());
        if (nVersion == LEGACY_BLS_INDEXED_QUORUM_VERSION || nVersion == BASIC_BLS_INDEXED_QUORUM_VERSION)
        {
            quorumIndex = ser_readdata16(s);
        }
        DynamicBitSetFormatter dyn_ser;
        dyn_ser.Unser(s, signers);
        dyn_ser.Unser(s, validMembers);
        bool fLegacyScheme = (nVersion == LEGACY_BLS_NON_INDEXED_QUORUM_VERSION || nVersion == LEGACY_BLS_INDEXED_QUORUM_VERSION);
        quorumPublicKey.Unserialize(s, fLegacyScheme, false);
        SerializationOpTail(s, CSerActionUnserialize());
    }

public:
    bool IsNull() const
    {
        if (std::count(signers.begin(), signers.end(), true) ||
            std::count(validMembers.begin(), validMembers.end(), true)) {
            return false;
        }
        if (quorumPublicKey.IsValid() ||
            !quorumVvecHash.IsNull() ||
            membersSig.IsValid() ||
            quorumSig.IsValid()) {
            return false;
        }
        return true;
    }

    void ToJson(UniValue& obj) const
    {
        obj.setObject();
        obj.pushKV("version", int{nVersion});
        obj.pushKV("llmqType", int(llmqType));
        obj.pushKV("quorumHash", quorumHash.ToString());
        obj.pushKV("quorumIndex", quorumIndex);
        obj.pushKV("signersCount", CountSigners());
        obj.pushKV("signers", BitsVectorToHexStr(signers));
        obj.pushKV("validMembersCount", CountValidMembers());
        obj.pushKV("validMembers", BitsVectorToHexStr(validMembers));
        obj.pushKV("quorumPublicKey", quorumPublicKey.ToString(nVersion == LEGACY_BLS_NON_INDEXED_QUORUM_VERSION || nVersion == LEGACY_BLS_INDEXED_QUORUM_VERSION));
        obj.pushKV("quorumVvecHash", quorumVvecHash.ToString());
        obj.pushKV("quorumSig", quorumSig.ToString());
        obj.pushKV("membersSig", membersSig.ToString());
    }

private:
    static std::string BitsVectorToHexStr(const std::vector<bool>& vBits)
    {
        std::vector<uint8_t> vBytes((vBits.size() + 7) / 8);
        for (const auto i : irange::range(vBits.size())) {
            vBytes[i / 8] |= vBits[i] << (i % 8);
        }
        return HexStr(vBytes);
    }
};
using CFinalCommitmentPtr = std::unique_ptr<CFinalCommitment>;

class CFinalCommitmentTxPayload
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_QUORUM_COMMITMENT;
    static constexpr uint16_t CURRENT_VERSION = 1;
public:
    uint16_t nVersion{CURRENT_VERSION};
    uint32_t nHeight{std::numeric_limits<uint32_t>::max()};
    CFinalCommitment commitment;

public:
    SERIALIZE_METHODS(CFinalCommitmentTxPayload, obj)
    {
        READWRITE(obj.nVersion, obj.nHeight, obj.commitment);
    }

    void ToJson(UniValue& obj) const
    {
        obj.setObject();
        obj.pushKV("version", int{nVersion});
        obj.pushKV("height", int(nHeight));

        UniValue qcObj;
        commitment.ToJson(qcObj);
        obj.pushKV("commitment", qcObj);
    }
};

bool CheckLLMQCommitment(const CTransaction& tx, const CBlockIndex* pindexPrev, CValidationState& state);

} // namespace llmq

#endif // BITCOIN_LLMQ_COMMITMENT_H
