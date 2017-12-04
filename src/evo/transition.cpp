// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tinyformat.h"
#include "messagesigner.h"
#include "clientversion.h"
#include "transition.h"
#include "utilstrencodings.h"

uint256 CTransition::ComputeHash() const {
    CHashWriter hw(SER_GETHASH, CLIENT_VERSION);
    hw << *this;
    return hw.GetHash();
}

uint256 CTransition::GetHash() const {
    LOCK(const_cast<CTransition*>(this)->csCachedHash);
    if (cachedHash.IsNull())
        const_cast<CTransition*>(this)->cachedHash = ComputeHash();
    return cachedHash;
}

std::string CTransition::ToString() const {
    std::string str;
    str += strprintf("CTransition(hash=%s, ver=%d, fee=%d, hashRegTx=%s, hashPrevTransition=%s, hashDataMerkleRoot=%s)\n",
                     GetHash().ToString().substr(0,10),
                     nVersion,
                     nFee,
                     hashRegTx.ToString(),
                     hashPrevTransition.ToString(),
                     hashDataMerkleRoot.ToString());
    return str;
}

std::string CTransition::MakeSignMessage() const {
    std::stringstream ss;
    ss << nVersion;
    ss << "|" << action;
    ss << "|" << nFee;
    ss << "|" << hashRegTx.ToString();
    ss << "|" << hashPrevTransition.ToString();
    switch (action) {
        case Transition_UpdateData:
            ss << "|" << hashDataMerkleRoot.ToString();
            break;
        case Transition_ResetKey:
            ss << "|" << HexStr(newPubKey.begin(), newPubKey.end());
            break;
        case Transition_CloseAccount:
            // nothing
            break;
        default:
            assert(false);
    }
    return ss.str();
}
