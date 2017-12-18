// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "messagesigner.h"
#include "rpc/server.h"
#include "utilmoneystr.h"
#include "validation.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif//ENABLE_WALLET

#include "evo/subtx.h"
#include "evo/users.h"
#include "evo/tsvalidation.h"
#include "evo/tsmempool.h"

void TsToJSON(const CTransition& ts, const uint256 &hashBlock, UniValue& entry)
{
    entry.setObject();

    uint256 tsid = ts.GetHash();
    entry.push_back(Pair("tsid", tsid.GetHex()));
    entry.push_back(Pair("size", (int)::GetSerializeSize(ts, SER_NETWORK, PROTOCOL_VERSION)));
    entry.push_back(Pair("version", ts.nVersion));
    entry.push_back(Pair("fee", ValueFromAmount(ts.nFee)));
    entry.push_back(Pair("hashRegTx", ts.hashRegTx.GetHex()));
    entry.push_back(Pair("hashPrevTransition", ts.hashPrevTransition.GetHex()));
    entry.push_back(Pair("vchUserSigSize", (int)ts.vchUserSig.size()));
    entry.push_back(Pair("vvchQuorumSigsSize", (int)::GetSerializeSize(ts.vvchQuorumSigs, SER_NETWORK, PROTOCOL_VERSION)));

    switch (ts.action) {
        case Transition_UpdateData:
            entry.push_back(Pair("action", "updateData"));
            entry.push_back(Pair("hashDataMerkleRoot", ts.hashDataMerkleRoot.GetHex()));
            break;
        case Transition_ResetKey:
            entry.push_back(Pair("action", "resetKey"));
            entry.push_back(Pair("newKeyID", ts.newPubKeyID.ToString()));
            break;
        case Transition_CloseAccount:
            entry.push_back(Pair("action", "closeAccount"));
            break;
    }

    if (!hashBlock.IsNull()) {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex)) {
                entry.push_back(Pair("height", pindex->nHeight));
                entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", pindex->GetBlockTime()));
                entry.push_back(Pair("blocktime", pindex->GetBlockTime()));
            } else {
                entry.push_back(Pair("height", -1));
                entry.push_back(Pair("confirmations", 0));
            }
        }
    }
}

void SubTxToJSON(const CTransaction &tx, UniValue &entry) {
    entry.setObject();

    CSubTxData subTxData;
    if (!GetSubTxData(tx, subTxData))
        throw std::runtime_error("GetSubTxData failed");

    UniValue dataValue;
    subTxData.ToJSON(dataValue);

    if (tx.vout[0].nValue != 0)
        entry.push_back(Pair("topup", ValueFromAmount(tx.vout[0].nValue)));
    entry.push_back(Pair("data", dataValue));
}

static void User2Json(const CEvoUser &user, bool withSubTxAndTs, bool detailed, UniValue &json) {
    json.setObject();

    json.push_back(std::make_pair("uname", user.GetUserName()));
    json.push_back(std::make_pair("regtxid", user.GetRegTxId().ToString()));
    json.push_back(std::make_pair("pubkeyid", user.GetCurPubKeyID().ToString()));
    json.push_back(std::make_pair("credits", user.GetCreditBalance()));
    json.push_back(std::make_pair("data", user.GetCurHashDataMerkleRoot().ToString()));

    std::string state;
    if (user.IsClosed())
        state = "closed";
    else
        state = "open";
    json.push_back(std::make_pair("state", state));

    if (withSubTxAndTs) {
        UniValue subTxArr(UniValue::VARR);
        for (const auto &txid : user.GetSubTxIds()) {
            if (detailed) {
                UniValue e(UniValue::VOBJ);

                uint256 hashBlock;
                CTransaction tx;
                if (!GetTransaction(txid, tx, Params().GetConsensus(), hashBlock, false))
                    throw std::runtime_error(strprintf("SubTx %s not found", txid.ToString()));

                SubTxToJSON(tx, e);
                subTxArr.push_back(e);
            } else {
                subTxArr.push_back(txid.ToString());
            }
        }
        json.push_back(std::make_pair("subtx", subTxArr));

        std::vector<CTransition> transitions;
        evoUserDB->GetTransitionsForUser(user.GetRegTxId(), -1, transitions);

        UniValue transitionsArr(UniValue::VARR);
        for (CTransition ts : transitions) {
            if (detailed) {
                UniValue ts2(UniValue::VOBJ);
                TsToJSON(ts, uint256(), ts2);
                transitionsArr.push_back(ts2);
            } else {
                transitionsArr.push_back(ts.GetHash().ToString());
            }
        }

        json.push_back(std::make_pair("transitions", transitionsArr));
    }
}

static uint256 GetRegTxId(const std::string &regTxIdOrUserName) {
    if (IsHex(regTxIdOrUserName) && regTxIdOrUserName.size() == 64) {
        uint256 regTxId = ParseHashStr(regTxIdOrUserName, "regTxId");
        uint256 regTxId2;
        if (evoUserDB->GetUserIdByName(regTxIdOrUserName, regTxId2)) {
            throw std::runtime_error(strprintf("%s is ambiguous and could be a regTxId or a user name", regTxIdOrUserName));
        }
        return regTxId;
    }
    uint256 regTxId;
    if (evoUserDB->GetUserIdByName(regTxIdOrUserName, regTxId))
        return regTxId;
    throw std::runtime_error(strprintf("user %s not found", regTxIdOrUserName));
}

UniValue getuser(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 1 && params.size() != 2))
        throw std::runtime_error(
                "getuser <regTxId|username> (verbose)\n"
                "\nGet registered user in JSON format as defined by dash-schema.\n"
        );

    uint256 regTxId = GetRegTxId(params[0].get_str());
    bool verbose = false;
    if (params.size() > 1) {
        verbose = params[1].get_int() != 0;
    }

    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user))
        throw std::runtime_error(strprintf("failed to read user %s from db", params[0].get_str()));

    UniValue result;
    User2Json(user, true, verbose, result);
    return result;
}

// Allows to specify Dash address or priv key. In case of Dash address, the priv key is taken from the wallet
static CKey ParsePrivKey(const std::string &strKeyOrAddress) {
    CBitcoinAddress address;
    if (address.SetString(strKeyOrAddress) && address.IsValid()) {
#ifdef ENABLE_WALLET
        CKeyID keyId;
        CKey key;
        if (!address.GetKeyID(keyId) || !pwalletMain->GetKey(keyId, key))
            throw std::runtime_error(strprintf("non-wallet or invalid address %s", strKeyOrAddress));
        return key;
#else//ENABLE_WALLET
        throw std::runtime_error("addresses not supported in no-wallet builds");
#endif//ENABLE_WALLET
    }

    CBitcoinSecret secret;
    if (!secret.SetString(strKeyOrAddress) || !secret.IsValid())
        throw std::runtime_error(strprintf("invalid priv-key/address %s", strKeyOrAddress));
    return secret.GetKey();
}

static CKey GetKeyFromParamsOrWallet(const UniValue &params, int paramPos, const uint256 &regTxId) {
    if (params.size() > paramPos)
        return ParsePrivKey(params[paramPos].get_str());

#ifdef ENABLE_WALLET
    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user)) {
        throw std::runtime_error(strprintf("user %s not found", regTxId.ToString()));
    }

    const CKeyID &pubKeyID = user.GetCurPubKeyID();
    CKey key;
    if (!pwalletMain->GetKey(pubKeyID, key)) {
        throw std::runtime_error(strprintf("wallet key with id %s not found", pubKeyID.ToString()));
    }
    return key;
#else//ENABLE_WALLET
    throw std::runtime_error("unable to get key from wallet in no-wallet builds");
#endif//ENABLE_WALLET
}

static uint256 GetLastTransitionFromParams(const UniValue& params, int paramPos, const uint256 &regTxId) {
    if (params.size() > paramPos)
        return ParseHashStr(params[paramPos].get_str(), "hashLastTransition");

    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user))
        throw std::runtime_error(strprintf("user %s not found", regTxId.ToString()));
    return user.GetHashLastTransition();
}

UniValue createrawsubtx(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
        throw std::runtime_error(
                "createrawsubtx <type> args...\n"
                "\nCreates a raw (unfunded/unsigned) SubTx. Arguments depend on type of SubTx to be created.\n"
                "Arguments that expect a key can be either a private key or a Dash address. In case\n"
                "a Dash address is provided, the private key is looked up in the local wallet.\n"
                "\nAvailable types:\n"
                "  createrawsubtx register <username> <key> <topup>             - Create account register SubTx\n"
                "  createrawsubtx topup    <regTxId|username> <topup>           - Create account topup SubTx\n"
        );

    CDataStream ds(SER_DISK, CLIENT_VERSION);
    CAmount creditBurnAmount = 0;

    std::string action = params[0].get_str();

    if (action == "register") {
        std::string userName = params[1].get_str();
        CKey key = ParsePrivKey(params[2].get_str());

        if (!ParseMoney(params[3].get_str(), creditBurnAmount))
            throw std::runtime_error(strprintf("failed to parse fee: %s", params[1].get_str()));

        CSubTxData subTxData;
        subTxData.action = SubTxAction_Register;
        subTxData.userName = userName;
        subTxData.pubKeyID = key.GetPubKey().GetID();
        if (!subTxData.Sign(key))
            throw std::runtime_error("failed to sign data");

        ds << subTxData;
    } else if (action == "topup") {
        uint256 regTxId = GetRegTxId(params[1].get_str());
        if (!ParseMoney(params[2].get_str(), creditBurnAmount))
            throw std::runtime_error(strprintf("failed to parse fee: %s", params[1].get_str()));

        CSubTxData subTxData;
        subTxData.action = SubTxAction_TopUp;
        subTxData.regTxId = regTxId;

        ds << subTxData;
    } else {
        throw std::runtime_error("invalid type: " + action);
    }

    CMutableTransaction rawTx;
    CScript script;
    script << OP_SUBSCRIPTION;
    script << std::vector<unsigned char>(ds.begin(), ds.end());

    CTxOut txOut(creditBurnAmount, script);
    rawTx.vout.push_back(txOut);

    return EncodeHexTx(rawTx);
}

#ifdef ENABLE_WALLET
extern UniValue fundrawtransaction(const UniValue& params, bool fHelp);
extern UniValue signrawtransaction(const UniValue& params, bool fHelp);

UniValue createsubtx(const UniValue& params, bool fHelp)
{
    if (params.size() == 0 || fHelp) {
        throw std::runtime_error(
                "createsubtx <type> args...\n"
                "\nCreates, funds and signs a SubTx. Arguments are the same as for createrawsubtx\n"
        );
    }

    UniValue rawSubTx = createrawsubtx(params, fHelp);

    UniValue fundParams(UniValue::VARR);
    fundParams.push_back(rawSubTx);
    UniValue fundResult = fundrawtransaction(fundParams, false);
    UniValue fundedTx = fundResult["hex"];

    UniValue signParams(UniValue::VARR);
    signParams.push_back(fundedTx);
    UniValue signedTx = signrawtransaction(signParams, false);

    return signedTx;
}
#endif//ENABLE_WALLET

UniValue createrawtransition(const UniValue& params, bool fHelp) {
    if (fHelp || (params.size() != 4 && params.size() != 5))
        throw std::runtime_error(
                "createrawtransition <type> args...\n"
                "\nCreates a raw transition. Arguments depend on type of transition to be created.\n"
                "Arguments that expect a key can be either a private key or a Dash address. In case\n"
                "a Dash address is provided, the private key is looked up in the local wallet.\n"
                "\nAvailable types:\n"
                "  createrawtransition update   <regTxId|username> <fee> <merkleRoot> (<prevTransition>) - Update account data\n"
                "  createrawtransition resetkey <regTxId|username> <fee> <newKey>     (<prevTransition>) - Reset user key\n"
                "  createrawtransition close    <regTxId|username> <fee>              (<prevTransition>) - Close account\n"
        );

    std::string action = params[0].get_str();

    CTransition ts;
    ts.nVersion = CTransition::CURRENT_VERSION;
    ts.hashRegTx = GetRegTxId(params[1].get_str());
    if (!ParseMoney(params[2].get_str(), ts.nFee))
        throw std::runtime_error(strprintf("invalid fee %s", params[2].get_str()));

    if (action == "update") {
        ts.action = Transition_UpdateData;
        ts.hashDataMerkleRoot = ParseHashStr(params[3].get_str(), "merkleRoot");
        ts.hashPrevTransition = GetLastTransitionFromParams(params, 4, ts.hashRegTx);
    } else if (action == "resetkey") {
        ts.action = Transition_ResetKey;
        ts.newPubKeyID = ParsePrivKey(params[3].get_str()).GetPubKey().GetID();
        ts.hashPrevTransition = GetLastTransitionFromParams(params, 4, ts.hashRegTx);
    } else if (action == "close") {
        ts.action = Transition_CloseAccount;
    }

    CDataStream ds(SER_DISK, CLIENT_VERSION);
    ds << ts;
    return HexStr(ds.begin(), ds.end());
}

UniValue signrawtransition(const UniValue& params, bool fHelp) {
    if (fHelp || (params.size() != 1) && params.size() != 2)
        throw std::runtime_error(
                "signrawtransition <hexTs> (<key>)\n"
                "\nSigns a raw transition. If the key is omitted, it will lookup the current pubKey of the user and\n"
                "then try to get the private key from the wallet.\n"
        );

    std::string hexTs = params[0].get_str();
    CDataStream ds(ParseHex(hexTs), SER_DISK, CLIENT_VERSION);

    CTransition ts;
    ds >> ts;

    CKey userKey = GetKeyFromParamsOrWallet(params, 1, ts.hashRegTx);
    if (!CMessageSigner::SignMessage(ts.MakeSignMessage(), ts.vchUserSig, userKey))
        throw std::runtime_error(strprintf("could not sign transition for for user %s. keyId=%s", ts.hashRegTx.ToString(), userKey.GetPubKey().GetID().ToString()));

    CDataStream ds2(SER_DISK, CLIENT_VERSION);
    ds2 << ts;
    return HexStr(ds2.begin(), ds2.end());
}

UniValue createtransition(const UniValue& params, bool fHelp) {
    if (fHelp || (params.size() != 4 && params.size() != 5))
        throw std::runtime_error(
                "createtransition <type> args...\n"
                "\nCreates a raw transition and signs it. Arguments are the same as for createrawtransition.\n"
        );

    UniValue rawTs = createrawtransition(params, fHelp);

    UniValue signParams(UniValue::VARR);
    signParams.push_back(rawTs.get_str());
    UniValue signedTs = signrawtransition(signParams, false);
    return signedTs;
}

UniValue sendrawtransition(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
                "sendrawtransition <hexTs>\n"
                "\nSends a signed transition to the network.\n"
        );

    std::string hexTs = params[0].get_str();
    CDataStream ds(ParseHex(hexTs), SER_DISK, CLIENT_VERSION);

    CTransition ts;
    ds >> ts;

    tsMempool.AddTransition(ts);

    // TODO actually send it

    return UniValue(ts.GetHash().ToString());
}

UniValue gettransition(const UniValue &params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
                "gettransition <tsHash>\n"
                "\nGet transition with hash <tsHash> and output a json object.\n"
        );

    uint256 tsHash = ParseHashStr(params[0].get_str(), "tsHash");

    CTransition ts;
    if (!evoUserDB->GetTransition(tsHash, ts)) {
        if (!tsMempool.GetTransition(tsHash, ts))
            throw std::runtime_error("transition not found");
    }

    uint256 blockHash;
    evoUserDB->GetTransitionBlockHash(ts.GetHash(), blockHash);

    UniValue result;
    TsToJSON(ts, blockHash, result);
    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "evo",                "getuser",                &getuser,                true  },
    { "evo",                "createrawsubtx",         &createrawsubtx,         true  },
    { "evo",                "createrawtransition",    &createrawtransition,    true  },
    { "evo",                "createtransition",       &createtransition,       true  },
    { "evo",                "signrawtransition",      &signrawtransition,      true  },
    { "evo",                "sendrawtransition",      &sendrawtransition,      true  },
    { "evo",                "gettransition",          &gettransition,          true  },

#ifdef ENABLE_WALLET
        // createsubtx requires the wallet to be enabled to fund the SubTx
    { "evo",                "createsubtx",            &createsubtx,            true  },
#endif//ENABLE_WALLET
};

void RegisterEvoRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
