// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "core_io.h"
#include "init.h"
#include "rpc/server.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "wallet/wallet.h"

#include "evo/subtx.h"
#include "evo/users.h"

static UniValue User2Json(const CEvoUser &user) {
    UniValue json(UniValue::VOBJ);
    json.push_back(std::make_pair("uname", user.GetUserName()));
    json.push_back(std::make_pair("regtxid", user.GetRegTxId().ToString()));
    json.push_back(std::make_pair("pubkey", HexStr(user.GetCurPubKey())));
    json.push_back(std::make_pair("credits", user.GetCreditBalance()));

    UniValue subTxIdArr(UniValue::VARR);
    for (const auto &txid : user.GetSubTxIds()) {
        subTxIdArr.push_back(txid.ToString());
    }
    json.push_back(std::make_pair("subtx", subTxIdArr));

    std::string state;
    if (user.IsClosed())
        state = "closed";
    else
        state = "open";
    json.push_back(std::make_pair("state", state));

    return json;
}

UniValue getuser(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
                "getuser <regTxId|username>\n"
                "\nGet registered user in JSON format as defined by dash-schema.\n"
        );

    std::string regTxIdOrUserName = params[0].get_str();

    uint256 regTxId;
    if (!evoUserDB->GetUserIdByName(regTxIdOrUserName, regTxId)) {
        if (!IsHex(regTxIdOrUserName))
            throw std::runtime_error(strprintf("user %s not found", regTxIdOrUserName));
        regTxId.SetHex(regTxIdOrUserName);
        if (!evoUserDB->UserExists(regTxId))
            throw std::runtime_error(strprintf("user %s not found", regTxIdOrUserName));
    }

    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user))
        throw std::runtime_error(strprintf("failed to read user %s from db", regTxIdOrUserName));

    return User2Json(user);
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

UniValue createrawsubtx(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() == 0)
        throw std::runtime_error(
                "createrawsubtx <type> args...\n"
                "\nCreates a raw (unfunded/unsigned) SubTx. Arguments depend on type of SubTx to be created.\n"
                "Arguments that expect a key can be either a private key or a Dash address. In case\n"
                "a Dash address is provided, the private key is looked up in the local wallet.\n"
                "\nAvailable types:\n"
                "  createrawsubtx register <username> <key> <topup>    - Create account register SubTx\n"
                "  createrawsubtx topup    <regTxId> <topup>           - Create account topup SubTx\n"
                "  createrawsubtx resetkey <regTxId> <newKey> <oldKey> - Create account reset SubTx\n"
                "  createrawsubtx close    <regTxId> <key>             - Create account close SubTx\n"
        );

    CDataStream subTxData(SER_DISK, CLIENT_VERSION);
    CAmount creditBurnAmount = 0;

    std::string action = params[0].get_str();

    if (action == "register") {
        std::string userName = params[1].get_str();
        CKey key = ParsePrivKey(params[2].get_str());

        if (!ParseMoney(params[3].get_str(), creditBurnAmount))
            throw std::runtime_error(strprintf("failed to parse fee: %s", params[1].get_str()));

        CSubTxRegister data(userName, key.GetPubKey());
        if (!data.Sign(key))
            throw std::runtime_error("failed to sign data");

        subTxData << data;
    } else if (action == "topup") {
        uint256 regTxId = ParseHashStr(params[1].get_str(), "regTxId");
        if (!ParseMoney(params[2].get_str(), creditBurnAmount))
            throw std::runtime_error(strprintf("failed to parse fee: %s", params[1].get_str()));

        CSubTxTopUp data(regTxId);

        subTxData << data;
    } else if (action == "resetkey") {
        uint256 regTxId = ParseHashStr(params[1].get_str(), "regTxId");
        CKey newKey = ParsePrivKey(params[2].get_str());
        CKey oldKey = ParsePrivKey(params[3].get_str());

        CSubTxResetKey data(regTxId, newKey.GetPubKey());
        if (!data.Sign(oldKey))
            throw std::runtime_error("failed to sign data");

        subTxData << data;
    } else if (action == "close") {
        uint256 regTxId = ParseHashStr(params[1].get_str(), "regTxId");
        CKey key = ParsePrivKey(params[2].get_str());

        CSubTxClose data(regTxId);
        if (!data.Sign(key))
            throw std::runtime_error("failed to sign data");

        subTxData << data;
    } else {
        throw std::runtime_error("invalid type: " + action);
    }

    CMutableTransaction rawTx;
    CScript script;
    script << OP_SUBSCRIPTION;
    script << std::vector<unsigned char>(subTxData.begin(), subTxData.end());

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