// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_PRIMITIVES_TRANSITION_H
#define DASH_PRIMITIVES_TRANSITION_H

#include "amount.h"
#include "uint256.h"
#include "sync.h"
#include "key.h"
#include "tinyformat.h"

#include <cstdint>
#include <memory>
#include <atomic>

enum TransitionAction {
    Transition_Invalid = 0,
    Transition_UpdateData = 1,
    Transition_ResetKey = 2,
    Transition_CloseAccount = 3,
};

class CTransition {
public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION = 0x00010000; // Evo 1.0.0

    int32_t nVersion{};
    TransitionAction action{Transition_Invalid};
    CAmount nFee{};
    uint256 hashRegTx;
    uint256 hashPrevTransition;

    // only valid for type == Transition_UpdateData
    uint256 hashDataMerkleRoot;

    // only valid for type == Transition_ResetKey
    CKeyID newPubKeyID;

    std::vector<unsigned char> vchUserSig;
    std::vector<std::vector<unsigned char>> vvchQuorumSigs;

    // memory only
    CCriticalSection csCachedHash;
    uint256 cachedHash;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(VARINT(this->nVersion));

        int _action = action;
        READWRITE(VARINT(_action));
        action = (TransitionAction)_action;

        READWRITE(VARINT(nFee));
        READWRITE(hashRegTx);
        READWRITE(hashPrevTransition);

        switch (action) {
            case Transition_UpdateData:
                READWRITE(hashDataMerkleRoot);
                break;
            case Transition_ResetKey:
                READWRITE(newPubKeyID);
                break;
            case Transition_CloseAccount:
                // nothing
                break;
            default:
                throw std::ios_base::failure(strprintf("invalid transition action %d", action));

        }

        READWRITE(vchUserSig);
        READWRITE(vvchQuorumSigs);
    }

public:
    CTransition() {}
    CTransition(const CTransition &r) { *this = r; }

    CTransition &operator=(const CTransition &r) {
        this->nVersion = r.nVersion;
        this->action = r.action;
        this->nFee = r.nFee;
        this->hashRegTx = r.hashRegTx;
        this->hashPrevTransition = r.hashPrevTransition;
        this->hashDataMerkleRoot = r.hashDataMerkleRoot;
        this->newPubKeyID = r.newPubKeyID;
        this->vchUserSig = r.vchUserSig;
        this->vvchQuorumSigs = r.vvchQuorumSigs;
        this->cachedHash.SetNull();
        return *this;
    }

    uint256 ComputeHash() const;
    // Warning, this should only be used on transitions which are not changed afterwards
    uint256 GetHash() const;

    std::string ToString() const;

    std::string MakeSignMessage() const;
};

#endif //DASH_PRIMITIVES_TRANSITION_H
