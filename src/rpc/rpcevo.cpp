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
#include "wallet/wallet.h"

#include "evo/subtx.h"
#include "evo/users.h"

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
    json.push_back(std::make_pair("pubkey", HexStr(user.GetCurPubKey())));
    json.push_back(std::make_pair("credits", user.GetCreditBalance()));

    }

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
    if (address.SetString(strKeyOrAddress)) {
        CKeyID keyId;
        CKey key;
        if (!address.GetKeyID(keyId) || !pwalletMain->GetKey(keyId, key))
            throw std::runtime_error(strprintf("non-wallet or invalid address %s", strKeyOrAddress));
        return key;
    }

    CBitcoinSecret secret;
    if (!secret.SetString(strKeyOrAddress))
        throw std::runtime_error(strprintf("invalid priv-key/address %s", strKeyOrAddress));
    return secret.GetKey();
}

static CKey GetKeyFromParamsOrWallet(const UniValue &params, int paramPos, const uint256 &regTxId) {
    if (params.size() > paramPos)
        return ParsePrivKey(params[paramPos].get_str());

    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user)) {
        throw std::runtime_error(strprintf("user %s not found", regTxId.ToString()));
    }

    const CPubKey &pubKey = user.GetCurPubKey();
    CKey key;
    if (!pwalletMain->GetKey(pubKey.GetID(), key)) {
        throw std::runtime_error(strprintf("wallet key with id %s not found", pubKey.GetID().ToString()));
    }
    return key;
}

static uint256 GetLastTransitionFromParams(const UniValue& params, int paramPos, const uint256 &regTxId) {
    if (params.size() > paramPos)
        return ParseHashStr(params[paramPos].get_str(), "hashLastTransition");

    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user))
        throw std::runtime_error(strprintf("user %s not found", regTxId.ToString()));
    return user.GetLastTransition();
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
        subTxData.pubKey = key.GetPubKey();
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