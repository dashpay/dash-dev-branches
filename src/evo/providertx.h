// Copyright (c) 2018-2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_PROVIDERTX_H
#define BITCOIN_EVO_PROVIDERTX_H

#include <bls/bls.h>
#include <evo/specialtx.h>
#include <primitives/transaction.h>

#include <consensus/validation.h>
#include <key_io.h>
#include <netaddress.h>
#include <pubkey.h>
#include <univalue.h>

class CBlockIndex;
class CCoinsViewCache;
class CValidationState;

struct maybe_error{
    bool did_err{false};
    ValidationInvalidReason reason{ValidationInvalidReason::CONSENSUS};
    std::string_view error_str;

    constexpr maybe_error() = default;
    constexpr maybe_error(ValidationInvalidReason reasonIn, std::string_view err): did_err(true), reason(reasonIn), error_str(err) {};
};

class CProRegTx
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_PROVIDER_REGISTER;
    static constexpr uint16_t LEGACY_BLS_VERSION = 1;
    static constexpr uint16_t BASIC_BLS_VERSION = 2;

    [[nodiscard]] static constexpr auto GetVersion(const bool is_basic_scheme_active) -> uint16_t
    {
        return is_basic_scheme_active ? BASIC_BLS_VERSION : LEGACY_BLS_VERSION;
    }

    uint16_t nVersion{LEGACY_BLS_VERSION};                 // message version
    uint16_t nType{0};                                     // only 0 supported for now
    uint16_t nMode{0};                                     // only 0 supported for now
    COutPoint collateralOutpoint{uint256(), (uint32_t)-1}; // if hash is null, we refer to a ProRegTx output
    CService addr;
    CKeyID keyIDOwner;
    CBLSPublicKey pubKeyOperator;
    CKeyID keyIDVoting;
    uint16_t nOperatorReward{0};
    CScript scriptPayout;
    uint256 inputsHash; // replay protection
    std::vector<unsigned char> vchSig;

    SERIALIZE_METHODS(CProRegTx, obj)
    {
        READWRITE(
                obj.nVersion
        );
        if (obj.nVersion == 0 || obj.nVersion > BASIC_BLS_VERSION) {
            // unknown version, bail out early
            return;
        }
        READWRITE(
                obj.nType,
                obj.nMode,
                obj.collateralOutpoint,
                obj.addr,
                obj.keyIDOwner,
                CBLSPublicKeyVersionWrapper(const_cast<CBLSPublicKey&>(obj.pubKeyOperator), (obj.nVersion == LEGACY_BLS_VERSION)),
                obj.keyIDVoting,
                obj.nOperatorReward,
                obj.scriptPayout,
                obj.inputsHash
        );
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(obj.vchSig);
        }
    }

    // When signing with the collateral key, we don't sign the hash but a generated message instead
    // This is needed for HW wallet support which can only sign text messages as of now
    std::string MakeSignString() const;

    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", nVersion);
        obj.pushKV("collateralHash", collateralOutpoint.hash.ToString());
        obj.pushKV("collateralIndex", (int)collateralOutpoint.n);
        obj.pushKV("service", addr.ToString(false));
        obj.pushKV("ownerAddress", EncodeDestination(keyIDOwner));
        obj.pushKV("votingAddress", EncodeDestination(keyIDVoting));

        CTxDestination dest;
        if (ExtractDestination(scriptPayout, dest)) {
            obj.pushKV("payoutAddress", EncodeDestination(dest));
        }
        obj.pushKV("pubKeyOperator", pubKeyOperator.ToString(nVersion == LEGACY_BLS_VERSION));
        obj.pushKV("operatorReward", (double)nOperatorReward / 100);

        obj.pushKV("inputsHash", inputsHash.ToString());
    }

    maybe_error IsTriviallyValid(bool is_bls_legacy_scheme) const;
};

class CProUpServTx
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_PROVIDER_UPDATE_SERVICE;
    static constexpr uint16_t LEGACY_BLS_VERSION = 1;
    static constexpr uint16_t BASIC_BLS_VERSION = 2;

    [[nodiscard]] static constexpr auto GetVersion(const bool is_basic_scheme_active) -> uint16_t
    {
        return is_basic_scheme_active ? BASIC_BLS_VERSION : LEGACY_BLS_VERSION;
    }

    uint16_t nVersion{LEGACY_BLS_VERSION}; // message version
    uint256 proTxHash;
    CService addr;
    CScript scriptOperatorPayout;
    uint256 inputsHash; // replay protection
    CBLSSignature sig;

    SERIALIZE_METHODS(CProUpServTx, obj)
    {
        READWRITE(
                obj.nVersion
        );
        if (obj.nVersion == 0 || obj.nVersion > BASIC_BLS_VERSION) {
            // unknown version, bail out early
            return;
        }
        READWRITE(
                obj.proTxHash,
                obj.addr,
                obj.scriptOperatorPayout,
                obj.inputsHash
        );
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(
                    CBLSSignatureVersionWrapper(const_cast<CBLSSignature&>(obj.sig), (obj.nVersion == LEGACY_BLS_VERSION), true)
            );
        }
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", nVersion);
        obj.pushKV("proTxHash", proTxHash.ToString());
        obj.pushKV("service", addr.ToString(false));
        CTxDestination dest;
        if (ExtractDestination(scriptOperatorPayout, dest)) {
            obj.pushKV("operatorPayoutAddress", EncodeDestination(dest));
        }
        obj.pushKV("inputsHash", inputsHash.ToString());
    }

    maybe_error IsTriviallyValid(bool is_bls_legacy_scheme) const;
};

class CProUpRegTx
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_PROVIDER_UPDATE_REGISTRAR;
    static constexpr uint16_t LEGACY_BLS_VERSION = 1;
    static constexpr uint16_t BASIC_BLS_VERSION = 2;

    [[nodiscard]] static constexpr auto GetVersion(const bool is_basic_scheme_active) -> uint16_t
    {
        return is_basic_scheme_active ? BASIC_BLS_VERSION : LEGACY_BLS_VERSION;
    }

    uint16_t nVersion{LEGACY_BLS_VERSION}; // message version
    uint256 proTxHash;
    uint16_t nMode{0}; // only 0 supported for now
    CBLSPublicKey pubKeyOperator;
    CKeyID keyIDVoting;
    CScript scriptPayout;
    uint256 inputsHash; // replay protection
    std::vector<unsigned char> vchSig;

    SERIALIZE_METHODS(CProUpRegTx, obj)
    {
        READWRITE(
                obj.nVersion
        );
        if (obj.nVersion == 0 || obj.nVersion > BASIC_BLS_VERSION) {
            // unknown version, bail out early
            return;
        }
        READWRITE(
                obj.proTxHash,
                obj.nMode,
                CBLSPublicKeyVersionWrapper(const_cast<CBLSPublicKey&>(obj.pubKeyOperator), (obj.nVersion == LEGACY_BLS_VERSION)),
                obj.keyIDVoting,
                obj.scriptPayout,
                obj.inputsHash
        );
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(
                    obj.vchSig
            );
        }
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", nVersion);
        obj.pushKV("proTxHash", proTxHash.ToString());
        obj.pushKV("votingAddress", EncodeDestination(keyIDVoting));
        CTxDestination dest;
        if (ExtractDestination(scriptPayout, dest)) {
            obj.pushKV("payoutAddress", EncodeDestination(dest));
        }
        obj.pushKV("pubKeyOperator", pubKeyOperator.ToString(nVersion == LEGACY_BLS_VERSION));
        obj.pushKV("inputsHash", inputsHash.ToString());
    }

    maybe_error IsTriviallyValid(bool is_bls_legacy_scheme) const;
};

class CProUpRevTx
{
public:
    static constexpr auto SPECIALTX_TYPE = TRANSACTION_PROVIDER_UPDATE_REVOKE;
    static constexpr uint16_t LEGACY_BLS_VERSION = 1;
    static constexpr uint16_t BASIC_BLS_VERSION = 2;

    [[nodiscard]] static constexpr auto GetVersion(const bool is_basic_scheme_active) -> uint16_t
    {
        return is_basic_scheme_active ? BASIC_BLS_VERSION : LEGACY_BLS_VERSION;
    }

    // these are just informational and do not have any effect on the revocation
    enum {
        REASON_NOT_SPECIFIED = 0,
        REASON_TERMINATION_OF_SERVICE = 1,
        REASON_COMPROMISED_KEYS = 2,
        REASON_CHANGE_OF_KEYS = 3,
        REASON_LAST = REASON_CHANGE_OF_KEYS
    };

    uint16_t nVersion{LEGACY_BLS_VERSION}; // message version
    uint256 proTxHash;
    uint16_t nReason{REASON_NOT_SPECIFIED};
    uint256 inputsHash; // replay protection
    CBLSSignature sig;

    SERIALIZE_METHODS(CProUpRevTx, obj)
    {
        READWRITE(
                obj.nVersion
        );
        if (obj.nVersion == 0 || obj.nVersion > BASIC_BLS_VERSION) {
            // unknown version, bail out early
            return;
        }
        READWRITE(
                obj.proTxHash,
                obj.nReason,
                obj.inputsHash
        );
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(
                    CBLSSignatureVersionWrapper(const_cast<CBLSSignature&>(obj.sig), (obj.nVersion == LEGACY_BLS_VERSION), true)
            );
        }
    }

    std::string ToString() const;

    void ToJson(UniValue& obj) const
    {
        obj.clear();
        obj.setObject();
        obj.pushKV("version", nVersion);
        obj.pushKV("proTxHash", proTxHash.ToString());
        obj.pushKV("reason", (int)nReason);
        obj.pushKV("inputsHash", inputsHash.ToString());
    }

    maybe_error IsTriviallyValid(bool is_bls_legacy_scheme) const;
};

template <typename ProTx>
static maybe_error CheckInputsHash(const CTransaction& tx, const ProTx& proTx)
{
    if (uint256 inputsHash = CalcTxInputsHash(tx); inputsHash != proTx.inputsHash) {
        return {ValidationInvalidReason::CONSENSUS, "bad-protx-inputs-hash"};
    }

    return {};
}


#endif // BITCOIN_EVO_PROVIDERTX_H
