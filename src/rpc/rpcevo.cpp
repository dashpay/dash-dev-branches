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

#include "netbase.h"

#include "evo/specialtx.h"
#include "evo/providertx.h"
#include "evo/subtx.h"
#include "evo/users.h"
#include "evo/tsvalidation.h"
#include "evo/tsmempool.h"
#include "evo/deterministicmns.h"

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
                CTransactionRef tx;
                if (!GetTransaction(txid, tx, Params().GetConsensus(), hashBlock, false))
                    throw std::runtime_error(strprintf("SubTx %s not found", txid.ToString()));

                SubTxToJSON(*tx, e);
                subTxArr.push_back(e);
            } else {
                subTxArr.push_back(txid.ToString());
            }
        }
        json.push_back(std::make_pair("subtx", subTxArr));

        std::vector<CTransition> transitions;
        evoUserDB->GetTransitionsForUser(user.GetRegTxId(), -1, transitions);

        std::vector<CTransition> mempoolTransitions;
        tsMempool.GetTransitionsChain(user.GetHashLastTransition(), transitions.empty() ? uint256() : transitions.back().GetHash(), mempoolTransitions);
        transitions.insert(transitions.end(), mempoolTransitions.begin(), mempoolTransitions.end());

        UniValue transitionsArr(UniValue::VARR);
        for (const CTransition &ts : transitions) {
            if (detailed) {
                UniValue ts2(UniValue::VOBJ);
                uint256 blockHash;
                evoUserDB->GetTransitionBlockHash(ts.GetHash(), blockHash);
                TsToJSON(ts, blockHash, ts2);
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
    if (!evoUserDB->GetUser(regTxId, user)) {
        if (!includeMempool || !BuildUserFromMempool(regTxId, user))
            throw std::runtime_error(strprintf("failed to read user %s from db", request.params[0].get_str()));
        fromMempool = true;
    }

    if (includeMempool) {
        fromMempool |= TopupUserFromMempool(user);
        fromMempool |= ApplyUserTransitionsFromMempool(user);
    }

    UniValue result;
    User2Json(user, true, verbose, result);
    if (fromMempool)
        result.push_back(Pair("from_mempool", true));
    return result;
}

// Allows to specify Dash address or priv key. In case of Dash address, the priv key is taken from the wallet
static CKey ParsePrivKey(const std::string &strKeyOrAddress, bool allowAddresses = true) {
    CBitcoinAddress address;
    if (allowAddresses && address.SetString(strKeyOrAddress) && address.IsValid()) {
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

static CKey GetKeyFromParamsOrWallet(const UniValue &params, uint32_t paramPos, const uint256 &regTxId) {
    if (params.size() > paramPos)
        return ParsePrivKey(params[paramPos].get_str());

#ifdef ENABLE_WALLET
    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user) && !BuildUserFromMempool(regTxId, user)) {
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

static uint256 GetLastTransitionFromParams(const UniValue& params, uint32_t paramPos, const uint256 &regTxId) {
    if (params.size() > paramPos)
        return ParseHashStr(params[paramPos].get_str(), "hashLastTransition");

    CEvoUser user;
    if (!evoUserDB->GetUser(regTxId, user) && !BuildUserFromMempool(regTxId, user))
        throw std::runtime_error(strprintf("user %s not found", regTxId.ToString()));
    ApplyUserTransitionsFromMempool(user);
    return user.GetHashLastTransition();
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

    if (action == "register") {
        std::string userName = request.params[1].get_str();
        CKey key = ParsePrivKey(request.params[2].get_str());

        if (!ParseMoney(request.params[3].get_str(), creditBurnAmount))
            throw std::runtime_error(strprintf("failed to parse fee: %s", request.params[1].get_str()));

        CSubTxData subTxData;
        subTxData.action = SubTxAction_Register;
        subTxData.userName = userName;
        subTxData.pubKeyID = key.GetPubKey().GetID();
        if (!subTxData.Sign(key))
            throw std::runtime_error("failed to sign data");

        ds << subTxData;
    } else if (action == "topup") {
        uint256 regTxId = GetRegTxId(request.params[1].get_str());
        if (!ParseMoney(request.params[2].get_str(), creditBurnAmount))
            throw std::runtime_error(strprintf("failed to parse fee: %s", request.params[1].get_str()));

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
extern UniValue fundrawtransaction(const JSONRPCRequest& request);
extern UniValue signrawtransaction(const JSONRPCRequest& request);
extern UniValue sendrawtransaction(const JSONRPCRequest& request);

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
    if (request.fHelp || (request.params.size() != 4 && request.params.size() != 5))
        throw std::runtime_error(
                "createrawtransition type args...\n"
                "\nCreates a raw transition. Arguments depend on type of transition to be created.\n"
                "Arguments that expect a key can be either a private key or a Dash address. In case\n"
                "a Dash address is provided, the private key is looked up in the local wallet.\n"
                "If prevTransition is not specified, the given user is looked up and the last transition\n"
                "of that user is taken. This will also consider unconfirmed (only in mempool) users and\n"
                "transitions.\n"
                "\nAvailable types:\n"
                "  createrawtransition update   \"regTxId|username\" fee \"merkleRoot\" ( \"prevTransition\" ) - Update account data\n"
                "  createrawtransition resetkey \"regTxId|username\" fee \"newKey\"     ( \"prevTransition\" ) - Reset user key\n"
                "  createrawtransition close    \"regTxId|username\" fee              ( \"prevTransition\" ) - Close account\n"
                "\nExamples:\n"
                + HelpExampleCli("createrawtransition", "update \"bob\" 0.00001 \"1234123412341234123412341234123412341234123412341234123412341234\"")
                + HelpExampleCli("createrawtransition", "resetkey \"bob\" 0.00001 \"93Fd7XY2zF4q9YKTZUSFxLgp4Xs7MuaMnvY9kpvH7V8oXWqsCC1\"")
                + HelpExampleCli("createrawtransition", "close \"bob\" 0.00001")
        );

    std::string action = request.params[0].get_str();

    CTransition ts;
    ts.nVersion = CTransition::CURRENT_VERSION;
    ts.hashRegTx = GetRegTxId(request.params[1].get_str());
    if (!ParseMoney(request.params[2].get_str(), ts.nFee))
        throw std::runtime_error(strprintf("invalid fee %s", request.params[2].get_str()));

    if (action == "update") {
        ts.action = Transition_UpdateData;
        ts.hashDataMerkleRoot = ParseHashStr(request.params[3].get_str(), "merkleRoot");
        ts.hashPrevTransition = GetLastTransitionFromParams(request.params, 4, ts.hashRegTx);
    } else if (action == "resetkey") {
        ts.action = Transition_ResetKey;
        ts.newPubKeyID = ParsePrivKey(request.params[3].get_str()).GetPubKey().GetID();
        ts.hashPrevTransition = GetLastTransitionFromParams(request.params, 4, ts.hashRegTx);
    } else if (action == "close") {
        ts.action = Transition_CloseAccount;
    } else {
        throw std::runtime_error("invalid command: " + action);
    }

    CDataStream ds(SER_DISK, CLIENT_VERSION);
    ds << ts;
    return HexStr(ds.begin(), ds.end());
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

    CTransition ts;
    ds >> ts;

    CKey userKey = GetKeyFromParamsOrWallet(request.params, 1, ts.hashRegTx);
    if (!CMessageSigner::SignMessage(ts.MakeSignMessage(), ts.vchUserSig, userKey))
        throw std::runtime_error(strprintf("could not sign transition for for user %s. keyId=%s", ts.hashRegTx.ToString(), userKey.GetPubKey().GetID().ToString()));

    CDataStream ds2(SER_DISK, CLIENT_VERSION);
    ds2 << ts;
    return HexStr(ds2.begin(), ds2.end());
}

UniValue createtransition(const JSONRPCRequest& request) {
    if (request.fHelp || (request.params.size() != 4 && request.params.size() != 5))
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

UniValue sendrawtransition(const JSONRPCRequest& request) {
    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2))
        throw std::runtime_error(
                "sendrawtransition \"hexTs\" ( relay )\n"
                "\nSends a signed transition to the network.\n"
                "If relay is specified and set to false, the transition is only added to the mempool.\n"
                "\nExamples:\n"
                + HelpExampleCli("sendrawtransition", "\"myHexTs\"")
                + HelpExampleRpc("sendrawtransition", "\"myHexTs\", \"false\"")
        );

    std::string hexTs = request.params[0].get_str();
    bool relay = true;
    if (request.params.size() == 2) {
        relay = request.params[1].get_bool();
    }

    CDataStream ds(ParseHex(hexTs), SER_DISK, CLIENT_VERSION);

    CTransition ts;
    ds >> ts;

    tsMempool.AddTransition(ts);

    CValidationState state;
    if (CheckTransition(ts, true, true, state)) {
        if (relay) {
            CInv inv(MSG_TRANSITION, ts.GetHash());
            g_connman->RelayInv(inv, MIN_EVO_PROTO_VERSION);
        }
    } else {
        if (relay && (state.GetRejectCode() == REJECT_TS_ANCESTOR || state.GetRejectCode() == REJECT_TS_NOUSER || state.GetRejectCode() == REJECT_INSUFFICIENTFEE)) {
            tsMempool.AddWaitForRelay(ts.GetHash());
        }
        throw std::runtime_error(strprintf("transition %s not valid. state: %s", ts.GetHash().ToString(), FormatStateMessage(state)));
    }

    return UniValue(ts.GetHash().ToString());
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

    bool fromMempool = false;
    CTransition ts;
    if (!evoUserDB->GetTransition(tsHash, ts)) {
        if (!tsMempool.GetTransition(tsHash, ts))
            throw std::runtime_error("transition not found");
        fromMempool = true;
    }

    uint256 blockHash;
    evoUserDB->GetTransitionBlockHash(ts.GetHash(), blockHash);

    UniValue result;
    TsToJSON(ts, blockHash, result);
    if (fromMempool)
        result.push_back(Pair("from_mempool", true));
    return result;
}

#ifdef ENABLE_WALLET
void protx_register_help() {
    throw std::runtime_error(
            "protx register \"collateralAddress\" collateralAmount \"ipAndPort\" protocolVersion \"masternodeKey\" \"payoutAddress\"\n"
            "\nCreates and sends a ProTx to the network. The resulting transaction will move the specified amount\n"
            "to the address specified by collateralAddress and will then function as the collateral of your\n"
            "masternode.\n"
            "A few of the limitations you see in the arguments are temporary and might be lifted after DIP3\n"
            "is fully deployed.\n"
            "\nArguments:\n"
            "1. \"collateralAddress\"   (string, required) The dash address to send the collateral to.\n"
            "                         Must be a P2PKH address.\n"
            "2. \"collateralAmount\"    (numeric or string, required) The collateral amount.\n"
            "                         Must be exactly 1000 Dash.\n"
            "3. \"ipAndPort\"           (string, required) IP and port in the form \"IP:PORT\".\n"
            "                         Must be unique on the network.\n"
            "4. \"protocolVersion\"     (string, required) The protocol version of your masternode.\n"
            "                         Can be 0 to default to the clients protocol version\n"
            "5. \"ownerAddr\"           (string, required) The owner key used for payee updates and proposal voting.\n"
            "                         The private key belonging to this address be known in your wallet. The address must\n"
            "                         be unused and must differ from the collateralAddress\n"
            "6. \"operatorKeyAddr\"     (string, required) The operator key address. The private key does not have to be known by your wallet.\n"
            "                         It hat to match the private key which is later used when operating the masternode.\n"
            "                         If set to \"0\" or an empty string, ownerAddr will be used.\n"
            "7. \"payoutAddress\"       (string, required) The dash address to use for masternode reward payments\n"
            "                         Must match \"collateralAddress\"."
            "\nExamples:\n"
            + HelpExampleCli("protx", "register \"XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwG\" 1000 \"1.2.3.4:1234\" 0 \"93Fd7XY2zF4q9YKTZUSFxLgp4Xs7MuaMnvY9kpvH7V8oXWqsCC1\" XwnLY9Tf7Zsef8gMGL2fhWA9ZmMjt4KPwG")
    );
}

UniValue protx_register(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() != 8)
        protx_register_help();

    CBitcoinAddress collateralAddress(request.params[1].get_str());
    if (!collateralAddress.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid collaterall address: %s", request.params[1].get_str()));
    CScript collateralScript = GetScriptForDestination(collateralAddress.Get());

    CAmount collateralAmount;
    if (!ParseMoney(request.params[2].get_str(), collateralAmount))
        throw std::runtime_error(strprintf("invalid collateral amount %s", request.params[2].get_str()));
    if (collateralAmount != 1000 * COIN)
        throw std::runtime_error(strprintf("invalid collateral amount %d. only 1000 DASH is supported at the moment", collateralAmount));

    CTxOut collateralTxOut(collateralAmount, collateralScript);

    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_PROVIDER_REGISTER;
    tx.vout.emplace_back(collateralTxOut);

    CProRegTX ptx;
    ptx.nVersion = CProRegTX::CURRENT_VERSION;

    if (!Lookup(request.params[3].get_str().c_str(), ptx.addr, Params().GetDefaultPort(), false))
        throw std::runtime_error(strprintf("invalid network address %s", request.params[3].get_str()));

    if (!ParseInt32(request.params[4].get_str(), &ptx.nProtocolVersion))
        throw std::runtime_error(strprintf("invalid protocol version %s", request.params[4].get_str()));

    if (ptx.nProtocolVersion == 0)
        ptx.nProtocolVersion = PROTOCOL_VERSION;

    CKey keyOwner = ParsePrivKey(request.params[5].get_str(), true);
    CKeyID keyIDOperator = keyOwner.GetPubKey().GetID();
    if (request.params[6].get_str() != "0" && request.params[6].get_str() != "") {
        CBitcoinAddress address(request.params[6].get_str());
        if (!address.IsValid() || !address.GetKeyID(keyIDOperator))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid operator address: %s", request.params[7].get_str()));
    }

    CBitcoinAddress payoutAddress(request.params[7].get_str());
    if (!payoutAddress.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid payout address: %s", request.params[7].get_str()));

    ptx.keyIDOperator = keyIDOperator;
    ptx.keyIDOwner = keyOwner.GetPubKey().GetID();
    ptx.scriptPayout = GetScriptForDestination(payoutAddress.Get());
    ptx.vchSig.resize(65); // reserve so that fee calculation is correct

    CDataStream ds(CLIENT_VERSION, SER_NETWORK);
    ds << ptx;
    tx.extraPayload.assign(ds.begin(), ds.end());

    CAmount nFee;
    CFeeRate feeRate = CFeeRate(0);
    int nChangePos = -1;
    std::string strFailReason;
    std::set<int> setSubtractFeeFromOutputs;
    if (!pwalletMain->FundTransaction(tx, nFee, false, feeRate, nChangePos, strFailReason, false, false, setSubtractFeeFromOutputs, true, CNoDestination()))
        throw JSONRPCError(RPC_INTERNAL_ERROR, strFailReason);

    uint32_t collateralIndex = (uint32_t) - 1;
    for (uint32_t i = 0; i < tx.vout.size(); i++) {
        if (tx.vout[i] == collateralTxOut) {
            collateralIndex = i;
            break;
        }
    }
    assert(collateralIndex != (uint32_t) - 1);

    ptx.nCollateralIndex = collateralIndex;
    ptx.inputsHash = CalcTxInputsHash(tx);
    ptx.vchSig.clear();

    uint256 hash = ::SerializeHash(ptx);
    if (!CHashSigner::SignHash(hash, keyOwner, ptx.vchSig)) {
        throw std::runtime_error(strprintf("failed to sign provider tx"));
    }

    // re-serialize the payload (we only now have correct hashes and signatures)
    ds.clear();
    ds << ptx;
    tx.extraPayload.assign(ds.begin(), ds.end());

    LOCK(cs_main);
    CValidationState state;
    if (!CheckSpecialTx(tx, NULL, state))
        throw std::runtime_error(FormatStateMessage(state));

    ds.clear();
    ds << tx;

    JSONRPCRequest signReqeust;
    signReqeust.params.setArray();
    signReqeust.params.push_back(HexStr(ds.begin(), ds.end()));
    UniValue signResult = signrawtransaction(signReqeust);

    JSONRPCRequest sendRequest;
    sendRequest.params.setArray();
    sendRequest.params.push_back(signResult["hex"].get_str());
    return sendrawtransaction(sendRequest);
}

void protx_list_help() {
    throw std::runtime_error(
            "protx list (\"type\")\n"
            "\nLists all ProTxs in your wallet or on-chain, depending on the given type. If \"type\" is not\n"
            "specified, it defaults to \"wallet\". All types have the optional argument \"detailed\" which if set to\n"
            "\"true\" will result in a detailed list to be returned. If set to \"false\", only the hashes of the ProTx\n"
            "will be returned.\n"
            "\nAvailable types:\n"
            "  wallet (detailed)              - List only ProTx which are found in your wallet. This will also include ProTx which\n"
            "                                   failed PoSe verfication\n"
            "  valid (height) (detailed)      - List only ProTx which are active/valid at the given chain height. If height is not\n"
            "                                   specified, it defaults to the current chain-tip\n"
            "  registered (height) (detaileD) - List all ProTx which are registered at the given chain height. If height is not\n"
            "                                   specified, it defaults to the current chain-tip. This will also include ProTx\n"
            "                                   which failed PoSe verification at that height\n"
    );
}

UniValue BuildDMNListEntry(const uint256& hash, const CDeterministicMNCPtr& dmn, bool detailed) {
    if (!detailed)
        return hash.ToString();

    UniValue o(UniValue::VOBJ);

    o.push_back(Pair("proTxHash", hash.GetHex()));
    o.push_back(Pair("collateralIndex", (int)dmn->nCollateralIndex));

    UniValue stateObj;
    dmn->state->ToJson(stateObj);
    o.push_back(Pair("state", stateObj));

    int confirmations = GetUTXOConfirmations(COutPoint(hash, dmn->nCollateralIndex));
    o.push_back(Pair("confirmations", confirmations));

    return o;
}

UniValue protx_list(const JSONRPCRequest& request) {
    if (request.fHelp)
        protx_list_help();

    std::string type = "wallet";
    if (request.params.size() > 1)
        type = request.params[1].get_str();

    UniValue ret(UniValue::VARR);

    if (type == "wallet") {
        if (request.params.size() > 3)
            protx_list_help();

        bool detailed = request.params.size() > 2 ? ParseBoolV(request.params[2], "detailed") : false;

        LOCK2(cs_main, pwalletMain->cs_wallet);
        std::vector<COutPoint> vOutpts;
        pwalletMain->ListProTxCoins(vOutpts);

        for (const COutPoint& outpt : vOutpts) {
            const CWalletTx *wtx = pwalletMain->GetWalletTx(outpt.hash);
            assert(wtx);

            auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(outpt.hash);
            if (!dmn)
                continue;

            ret.push_back(BuildDMNListEntry(wtx->GetHash(), dmn, detailed));
        }
    } else if (type == "valid" || type == "registered") {
        if (request.params.size() > 4)
            protx_list_help();

        LOCK(cs_main);
        int height = request.params.size() > 2 ? ParseInt32V(request.params[2], "height") : chainActive.Height();
        if (height < 1 || height > chainActive.Height())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid height specified");

        bool detailed = request.params.size() > 3 ? ParseBoolV(request.params[3], "detailed") : false;

        CDeterministicMNList mnList = deterministicMNManager->GetListAtHeight(height);
        CDeterministicMNList::range_type range;

        if (type == "valid") {
            range = mnList.valid_range();
        } else if (type == "registered") {
            range = mnList.all_range();
        }
        for (const auto& dmn : range) {
            ret.push_back(BuildDMNListEntry(dmn->proTxHash, dmn, detailed));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid type specified");
    }

    return ret;
}

UniValue protx(const JSONRPCRequest& request) {
    if (request.params.empty()) {
        throw std::runtime_error(
                "protx \"command\" ...\n"
                "Set of commands to execute ProTx related actions.\n"
                "To get help on individual commands, use \"help protx command\".\n"
                "\nArguments:\n"
                "1. \"command\"        (string, required) The command to execute\n"
                "\nAvailable commands:\n"
                "  register    - Create and send ProTx to network\n"
                "  list        - List ProTxs\n"
        );
    }

    std::string command = request.params[0].get_str();

    if (command == "register") {
        return protx_register(request);
    } else if (command == "list") {
        return protx_list(request);
    } else {
        throw std::runtime_error("invalid command: " + command);
    }
}

#endif//ENABLE_WALLET

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
    // these require the wallet to be enabled to fund the transactions
    { "evo",                "createsubtx",            &createsubtx,            true, {}  },
    { "evo",                "protx",                  &protx,                  true, {}  },
#endif//ENABLE_WALLET
};

void RegisterEvoRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
