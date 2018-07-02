// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tinyformat.h"
#include "clientversion.h"
#include "transition.h"
#include "utilstrencodings.h"

uint256 CTransition::ComputeHash() const {
    return ::SerializeHash(*this);
}

uint256 CTransition::GetHash() const {
    return ComputeHash();
}

std::string CTransition::ToString() const {
    std::string str;
    str += strprintf("CTransition(hash=%s, ver=%d, fee=%d, hashRegTx=%s, hashPrevTransition=%s, hashSTPacket=%s)\n",
                     GetHash().ToString().substr(0,10),
                     nVersion,
                     nFee,
                     hashRegTx.ToString(),
                     hashPrevTransition.ToString(),
                     hashSTPacket.ToString());
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
            ss << "|" << hashSTPacket.ToString();
            break;
        case Transition_ResetKey:
            ss << "|" << newPubKeyID.ToString();
            break;
        case Transition_CloseAccount:
            // nothing
            break;
        default:
            assert(false);
    }
    return ss.str();
}
