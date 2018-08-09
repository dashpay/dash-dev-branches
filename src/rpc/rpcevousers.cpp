// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "messagesigner.h"
#include "net.h"
#include "rpc/server.h"
#include "txmempool.h"
#include "utilmoneystr.h"
#include "validation.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif//ENABLE_WALLET

#include "evo/specialtx.h"
#include "evo/subtx.h"
#include "evo/users.h"
#include "evo/user.h"

static UniValue User2Json(const CEvoUser &user, bool withSubTxAndTs, bool detailed) {
    UniValue json(UniValue::VOBJ);

    json.push_back(std::make_pair("uname", user.GetUserName()));
    json.push_back(std::make_pair("regtxid", user.GetRegTxId().ToString()));
    json.push_back(std::make_pair("pubkeyid", user.GetCurPubKeyID().ToString()));
    json.push_back(std::make_pair("credits", user.GetCreditBalance()));
    json.push_back(std::make_pair("data", user.GetCurHashSTPacket().ToString()));

    std::string state;
    if (user.IsClosed())
        state = "closed";
    else
        state = "open";
    json.push_back(std::make_pair("state", state));

    if (withSubTxAndTs) {
        UniValue subTxArr(UniValue::VARR);
        for (const auto &hashSubTx : evoUserManager->ListUserSubTxs(user.GetRegTxId())) {
            if (detailed) {
                UniValue e(UniValue::VOBJ);

                uint256 hashBlock;
                CTransactionRef tx;
                if (!GetTransaction(hashSubTx, tx, Params().GetConsensus(), hashBlock, false))
                    throw std::runtime_error(strprintf("SubTx %s not found", hashSubTx.ToString()));

                subTxArr.push_back(SubTxToJson(*tx));
            } else {
                subTxArr.push_back(hashSubTx.ToString());
            }
        }
        json.push_back(std::make_pair("subtx", subTxArr));

        // TODO include mempool
    }

    return json;
}

static uint256 GetRegTxId(const std::string &regTxIdOrUserName) {
    if (IsHex(regTxIdOrUserName) && regTxIdOrUserName.size() == 64) {
        uint256 regTxId = ParseHashStr(regTxIdOrUserName, "regTxId");
        uint256 regTxId2;
        if (evoUserManager->GetUserIdByName(regTxIdOrUserName, regTxId2)) {
            throw std::runtime_error(strprintf("%s is ambiguous and could be a regTxId or a user name", regTxIdOrUserName));
        }
        return regTxId;
    }
    uint256 regTxId;
    if (evoUserManager->GetUserIdByName(regTxIdOrUserName, regTxId))
        return regTxId;
    if (mempool.getRegTxIdFromUserName(regTxIdOrUserName, regTxId))
        return regTxId;
    throw std::runtime_error(strprintf("user %s not found", regTxIdOrUserName));
}

UniValue getuser(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2 && request.params.size() != 3))
        throw std::runtime_error(
                "getuser \"regTxId|username\" ( includeMempool verbose )\n"
                "\nGet registered user in JSON format as defined by dash-schema.\n"
                "\nExamples:\n"
                + HelpExampleCli("getuser", "\"bob\"")
                + HelpExampleRpc("getuser", "\"alice\"")
        );

    uint256 regTxId = GetRegTxId(request.params[0].get_str());
    bool verbose = false;
    bool includeMempool = true;
    if (request.params.size() > 1) {
        includeMempool = request.params[1].get_bool();
    }
    if (request.params.size() > 2) {
        verbose = request.params[2].get_bool();
    }

    CEvoUser user;
    bool fromMempool = false;
    if (!evoUserManager->GetUser(regTxId, user, true, &fromMempool)) {
        throw std::runtime_error(strprintf("user %s not found", request.params[0].get_str()));
    }

    UniValue result = User2Json(user, true, verbose);
    if (fromMempool)
        result.push_back(Pair("from_mempool", true));
    return result;
}

// TODO move this into a header
CKey ParsePrivKey(const std::string &strKeyOrAddress, bool allowAddresses);

static CKey GetKeyFromParamsOrWallet(const UniValue &params, int paramPos, const uint256 &regTxId) {
    if (params.size() > paramPos)
        return ParsePrivKey(params[paramPos].get_str(), true);

#ifdef ENABLE_WALLET
    CEvoUser user;
    if (!evoUserManager->GetUser(regTxId, user, true)) {
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

static uint256 GetPrevSubTxFromParams(const UniValue& params, int paramPos, const uint256 &regTxId) {
    if (params.size() > paramPos)
        return ParseHashStr(params[paramPos].get_str(), "hashLastTransition");

    CEvoUser user;
    if (!evoUserManager->GetUser(regTxId, user, true))
        throw std::runtime_error(strprintf("user %s not found", regTxId.ToString()));
    return user.GetCurSubTx();
}

UniValue createrawsubtx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() == 0)
        throw std::runtime_error(
                "createrawsubtx type args...\n"
                "\nCreates a raw (unfunded/unsigned) SubTx. Arguments depend on type of SubTx to be created.\n"
                "Arguments that expect a key can be either a private key or a Dash address. In case\n"
                "a Dash address is provided, the private key is looked up in the local wallet.\n"
                "\nAvailable types:\n"
                "  createrawsubtx register \"username\" \"key\" \"topup\"             - Create account register SubTx\n"
                "  createrawsubtx topup    \"regTxId|username\" \"topup\"           - Create account topup SubTx\n"
                "\nExamples:\n"
                + HelpExampleCli("createrawsubtx", "register \"bob\" \"92KdqxzX7HCnxCtwt1yHENGrXq71SAxD4vrrsFArbSU2wUKdQCM\" 0.01")
                + HelpExampleCli("createrawsubtx", "register \"alice\" \"yT1a5WGcSJpDRQTvJRkCTKF8weK82qkt3A\" 0.01")
                + HelpExampleRpc("createrawsubtx", "\"topup\", \"alice\", \"0.02\"")
        );

    CDataStream ds(SER_DISK, CLIENT_VERSION);
    CAmount creditBurnAmount = 0;

    std::string action = request.params[0].get_str();

    CMutableTransaction rawTx;
    rawTx.nVersion = 3;

    if (action == "register") {
        std::string userName = request.params[1].get_str();
        CKey key = ParsePrivKey(request.params[2].get_str(), true);

        if (!ParseMoney(request.params[3].get_str(), creditBurnAmount))
            throw std::runtime_error(strprintf("failed to parse fee: %s", request.params[1].get_str()));

        CSubTxRegister subTx;
        subTx.userName = userName;
        subTx.pubKeyID = key.GetPubKey().GetID();
        if (!CHashSigner::SignHash(subTx.GetSignHash(), key, subTx.vchSig)) {
            throw std::runtime_error("failed to sign subTx");
        }

        rawTx.nType = TRANSACTION_SUBTX_REGISTER;
        SetTxPayload(rawTx, subTx);
    } else if (action == "topup") {
        uint256 regTxId = GetRegTxId(request.params[1].get_str());
        if (!ParseMoney(request.params[2].get_str(), creditBurnAmount))
            throw std::runtime_error(strprintf("failed to parse fee: %s", request.params[1].get_str()));

        CSubTxTopup subTx;
        subTx.regTxId = regTxId;

        rawTx.nType = TRANSACTION_SUBTX_TOPUP;
        SetTxPayload(rawTx, subTx);
    } else {
        throw std::runtime_error("invalid type: " + action);
    }

    CScript script;
    script << OP_RETURN;

    CTxOut txOut(creditBurnAmount, script);
    rawTx.vout.push_back(txOut);

    return EncodeHexTx(rawTx);
}

#ifdef ENABLE_WALLET
extern UniValue fundrawtransaction(const JSONRPCRequest& request);
extern UniValue signrawtransaction(const JSONRPCRequest& request);

UniValue createsubtx(const JSONRPCRequest& request)
{
    if (request.params.size() == 0 || request.fHelp) {
        throw std::runtime_error(
                "createsubtx args...\n"
                "\nCreates, funds and signs a SubTx. Arguments are the same as for createrawsubtx\n"
        );
    }

    UniValue rawSubTx = createrawsubtx(request);

    JSONRPCRequest fundRequest;
    fundRequest.params.setArray();
    fundRequest.params.push_back(rawSubTx);
    UniValue fundResult = fundrawtransaction(fundRequest);
    UniValue fundedTx = fundResult["hex"];

    JSONRPCRequest signReqeust;
    signReqeust.params.setArray();
    signReqeust.params.push_back(fundedTx);
    UniValue signedTx = signrawtransaction(signReqeust);

    return signedTx;
}
#endif//ENABLE_WALLET

UniValue createrawtransition(const JSONRPCRequest& request) {
    if (request.fHelp || (request.params.size() != 3 && request.params.size() != 4 && request.params.size() != 5))
        throw std::runtime_error(
                "createrawtransition type args...\n"
                "\nCreates a raw transition. Arguments depend on type of transition to be created.\n"
                "Arguments that expect a key can be either a private key or a Dash address. In case\n"
                "a Dash address is provided, the private key is looked up in the local wallet.\n"
                "If prevTransition is not specified, the given user is looked up and the last transition\n"
                "of that user is taken. This will also consider unconfirmed (only in mempool) users and\n"
                "transitions.\n"
                "\nAvailable types:\n"
                "  createrawtransition update   \"regTxId|username\" fee \"hashSTPacket\" ( \"prevSubTx\" ) - Update account data\n"
                "  createrawtransition resetkey \"regTxId|username\" fee \"newKey\"     ( \"prevSubTx\" ) - Reset user key\n"
                "  createrawtransition close    \"regTxId|username\" fee              ( \"prevSubTx\" ) - Close account\n"
                "\nExamples:\n"
                + HelpExampleCli("createrawtransition", "update \"bob\" 0.00001 \"1234123412341234123412341234123412341234123412341234123412341234\"")
                + HelpExampleCli("createrawtransition", "resetkey \"bob\" 0.00001 \"93Fd7XY2zF4q9YKTZUSFxLgp4Xs7MuaMnvY9kpvH7V8oXWqsCC1\"")
                + HelpExampleCli("createrawtransition", "close \"bob\" 0.00001")
        );

    std::string action = request.params[0].get_str();

    uint256 regTxId = GetRegTxId(request.params[1].get_str());

    CAmount credetFee;
    if (!ParseMoney(request.params[2].get_str(), credetFee))
        throw std::runtime_error(strprintf("invalid fee %s", request.params[2].get_str()));

    CMutableTransaction rawTx;
    rawTx.nVersion = 3;

    if (action == "update") {
        CSubTxTransition subTx;
        subTx.regTxId = regTxId;
        subTx.creditFee = credetFee;
        subTx.hashPrevSubTx = GetPrevSubTxFromParams(request.params, 4, regTxId);
        subTx.hashSTPacket = ParseHashStr(request.params[3].get_str(), "hashSTPacket");

        rawTx.nType = TRANSACTION_SUBTX_TRANSITION;
        SetTxPayload(rawTx, subTx);
    } else if (action == "resetkey") {
        CSubTxResetKey subTx;
        subTx.regTxId = regTxId;
        subTx.creditFee = credetFee;
        subTx.hashPrevSubTx = GetPrevSubTxFromParams(request.params, 4, regTxId);
        subTx.newPubKeyId = ParsePrivKey(request.params[3].get_str(), true).GetPubKey().GetID();;

        rawTx.nType = TRANSACTION_SUBTX_RESETKEY;
        SetTxPayload(rawTx, subTx);
    } else if (action == "close") {
        CSubTxCloseAccount subTx;
        subTx.regTxId = regTxId;
        subTx.creditFee = credetFee;
        subTx.hashPrevSubTx = GetPrevSubTxFromParams(request.params, 4, regTxId);

        rawTx.nType = TRANSACTION_SUBTX_CLOSEACCOUNT;
        SetTxPayload(rawTx, subTx);
    }

    CDataStream ds(SER_DISK, CLIENT_VERSION);
    ds << rawTx;
    return HexStr(ds.begin(), ds.end());
}

template<typename SubTx>
void SignSubTxHelper(CMutableTransaction& tx, const CKey& key)
{
    SubTx subTx;
    if (!GetTxPayload(tx, subTx)) {
        throw std::runtime_error("invalid tx payload");
    }
    if (!CHashSigner::SignHash(subTx.GetSignHash(), key, subTx.vchSig)) {
        throw std::runtime_error("failed to sign subTx");
    }
    SetTxPayload(tx, subTx);
}

UniValue signrawtransition(const JSONRPCRequest& request) {
    if (request.fHelp || (request.params.size() != 1) && request.params.size() != 2)
        throw std::runtime_error(
                "signrawtransition \"hex_ts\" ( \"key\" )\n"
                "\nSigns a raw transition. If the key is omitted, it will lookup the current pubKey of the user and\n"
                "then try to get the private key from the wallet.\n"
                "\nExamples:\n"
                + HelpExampleCli("signrawtransition", "\"myHexTs\"")
                + HelpExampleRpc("signrawtransition", "\"myHexTs\"")
        );

    std::string hexTs = request.params[0].get_str();
    CDataStream ds(ParseHex(hexTs), SER_DISK, CLIENT_VERSION);

    CMutableTransaction rawTx;
    ds >> rawTx;
    ds.clear();

    uint256 regTxId = GetRegTxIdFromSubTx(rawTx);
    if (regTxId.IsNull()) {
        throw std::runtime_error("failed to get regTxId from subTx");
    }

    CKey userKey = GetKeyFromParamsOrWallet(request.params, 1, regTxId);
    if (!userKey.IsValid()) {
        throw std::runtime_error("invalid key");
    }

    if (rawTx.nType == TRANSACTION_SUBTX_REGISTER) {
        SignSubTxHelper<CSubTxRegister>(rawTx, userKey);
    } else if (rawTx.nType == TRANSACTION_SUBTX_RESETKEY) {
        SignSubTxHelper<CSubTxResetKey>(rawTx, userKey);
    } else if (rawTx.nType == TRANSACTION_SUBTX_CLOSEACCOUNT) {
        SignSubTxHelper<CSubTxCloseAccount>(rawTx, userKey);
    } else if (rawTx.nType == TRANSACTION_SUBTX_TRANSITION) {
        SignSubTxHelper<CSubTxTransition>(rawTx, userKey);
    } else {
        throw std::runtime_error("unknown tx type");
    }

    ds.clear();
    ds << rawTx;
    return HexStr(ds.begin(), ds.end());
}

UniValue createtransition(const JSONRPCRequest& request) {
    if (request.fHelp || (request.params.size() != 3 && request.params.size() != 4 && request.params.size() != 5))
        throw std::runtime_error(
                "createtransition args...\n"
                "\nCreates a raw transition and signs it. Arguments are the same as for createrawtransition.\n"
        );

    UniValue rawTs = createrawtransition(request);

    JSONRPCRequest signRequest;
    signRequest.params.setArray();
    signRequest.params.push_back(rawTs.get_str());
    UniValue signedTs = signrawtransition(signRequest);
    return signedTs;
}

UniValue sendrawtransaction(const JSONRPCRequest& request);

UniValue sendrawtransition(const JSONRPCRequest& request) {
    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2))
        throw std::runtime_error(
                "same as sendrawtransaction. Only for compatibility\n"
        );

    return sendrawtransaction(request);
}

UniValue gettransition(const JSONRPCRequest &request) {
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "gettransition \"tsHash\"\n"
                "\nGet transition with hash \"tsHash\" and output a json object.\n"
                "\nExamples:\n"
                + HelpExampleCli("gettransition", "\"tsHash\"")
                + HelpExampleRpc("gettransition", "\"tsHash\", \"false\"")
        );

    uint256 tsHash = ParseHashStr(request.params[0].get_str(), "tsHash");

    uint256 hashBlock;
    CTransactionRef tx;
    if (!GetTransaction(tsHash, tx, Params().GetConsensus(), hashBlock, false))
        throw std::runtime_error(strprintf("SubTx %s not found", tsHash.ToString()));

    bool fromMempool = mempool.get(tsHash) != nullptr;

    UniValue result = SubTxToJson(*tx);
    if (fromMempool)
        result.push_back(Pair("from_mempool", true));
    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "evo",                "getuser",                &getuser,                true, {"user", "include_mempool", "verbose"}  },
    { "evo",                "createrawsubtx",         &createrawsubtx,         true, {}  },
    { "evo",                "createrawtransition",    &createrawtransition,    true, {}  },
    { "evo",                "createtransition",       &createtransition,       true, {}  },
    { "evo",                "signrawtransition",      &signrawtransition,      true, {"hex_ts", "key"}  },
    { "evo",                "sendrawtransition",      &sendrawtransition,      true, {"hex_ts", "relay"}  },
    { "evo",                "gettransition",          &gettransition,          true, {"ts_hash"}  },

#ifdef ENABLE_WALLET
// createsubtx requires the wallet to be enabled to fund the SubTx
    { "evo",                "createsubtx",            &createsubtx,            true, {}  },
#endif//ENABLE_WALLET
};

void RegisterEvoUsersRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
