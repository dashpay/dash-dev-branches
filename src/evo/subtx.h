// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_SUBTX_H
#define DASH_SUBTX_H

#include <key.h>
#include "validation.h"
#include "pubkey.h"
#include "serialize.h"
#include "users.h"

static const int MAX_SUBTX_DATA_LEN = 256;
static const CAmount MIN_SUBTX_TOPUP = 0.0001 * COIN;

bool IsSubTx(const CTransaction &tx);
bool IsSubTxDataValid(const CTransaction &tx, CValidationState &state);

bool CheckSubTx(const CTransaction &tx, CValidationState &state);

bool ProcessSubTx(const CTransaction &tx, CValidationState &state);
bool UndoSubTx(const CTransaction &tx, CValidationState &state);

enum SubTxAction {
    SubTxAction_Invalid = -1,
    SubTxAction_Register = 1,
    SubTxAction_TopUp = 2,
    SubTxAction_ResetKey = 3,
    SubTxAction_Close = 4,
};

class CSubTxData {
protected:
    SubTxAction action{SubTxAction_Invalid};

public:
    CSubTxData(SubTxAction _action)
            : action(_action)
    {}
    virtual ~CSubTxData() {}

    SubTxAction  GetAction() const {
        return action;
    };

    virtual bool Check(const CTransaction &subTx, CValidationState &state) = 0;
    virtual bool Process(const CTransaction &subTx, CValidationState &state) = 0;
    virtual bool Undo(const CTransaction &subTx, CValidationState &state) = 0;

    static CSubTxData *Deserialize(const std::vector<unsigned char> &data);

protected:
    template <typename Stream, typename Operation>
    inline void BaseSerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        int _action = action;
        READWRITE(VARINT(_action));
        assert(action == _action);
        action = (SubTxAction)_action;
    }
};

class CSubTxRegister : public CSubTxData {
private:
    std::string userName;
    CPubKey pubKey;
    std::vector<unsigned char> vchSig;

public:
    CSubTxRegister() : CSubTxData(SubTxAction_Register) {}
    CSubTxRegister(const std::string &_userName, const CPubKey &_pubKey)
            : CSubTxData(SubTxAction_Register),
              userName(_userName),
              pubKey(_pubKey)
    {}

    const std::string &GetUserName() {
        return userName;
    }
    const CPubKey &GetPubKey() {
        return pubKey;
    }

    virtual bool Check(const CTransaction &subTx, CValidationState &state);
    virtual bool Process(const CTransaction &subTx, CValidationState &state);
    virtual bool Undo(const CTransaction &subTx, CValidationState &state);

    std::string MakeSignMessage() const;
    bool Sign(const CKey &key);

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        BaseSerializationOp(s, ser_action, nType, nVersion);
        READWRITE(userName);
        READWRITE(pubKey);
        READWRITE(vchSig);
    }
};

class CSubTxDataExistingUser : public CSubTxData {
protected:
    uint256 regTxId;

public:
    CSubTxDataExistingUser(SubTxAction _action, const uint256 &_regTxId = uint256())
            : CSubTxData(_action),
              regTxId(_regTxId)
    {}

    const uint256 &GetRegTxId() {
        return regTxId;
    }

    bool Check(const CTransaction &subTx, CValidationState &state) override;
    bool Process(const CTransaction &subTx, CValidationState &state) override;
    bool Undo(const CTransaction &subTx, CValidationState &state) override;

    virtual bool Check(const CTransaction &subTx, CEvoUser &user, CValidationState &state) = 0;
    virtual bool Process(const CTransaction &subTx, CEvoUser &user, CValidationState &state) = 0;
    virtual bool Undo(const CTransaction &subTx, CEvoUser &user, CValidationState &state) = 0;
};

class CSubTxTopUp : public CSubTxDataExistingUser {
public:
    CSubTxTopUp() : CSubTxDataExistingUser(SubTxAction_TopUp) {}
    CSubTxTopUp(const uint256 &_regTxId) : CSubTxDataExistingUser(SubTxAction_TopUp, _regTxId) {}

    virtual bool Check(const CTransaction &subTx, CEvoUser &user, CValidationState &state) override;
    virtual bool Process(const CTransaction &subTx, CEvoUser &user, CValidationState &state) override;
    virtual bool Undo(const CTransaction &subTx, CEvoUser &user, CValidationState &state) override;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        BaseSerializationOp(s, ser_action, nType, nVersion);
        READWRITE(regTxId);
    }
};

class CSubTxResetKey : public CSubTxDataExistingUser {
private:
    CPubKey newPubKey;
    std::vector<unsigned char> lastPubkeySig;

public:
    CSubTxResetKey() : CSubTxDataExistingUser(SubTxAction_ResetKey) {}
    CSubTxResetKey(const uint256 &_regTxId, const CPubKey &_newPubKey)
            : CSubTxDataExistingUser(SubTxAction_ResetKey, _regTxId),
              newPubKey(_newPubKey)
    {}

    virtual bool Check(const CTransaction &subTx, CEvoUser &user, CValidationState &state) override;
    virtual bool Process(const CTransaction &subTx, CEvoUser &user, CValidationState &state) override;
    virtual bool Undo(const CTransaction &subTx, CEvoUser &user, CValidationState &state) override;

    std::string MakeSignMessage() const;
    bool Sign(const CKey &key);

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        BaseSerializationOp(s, ser_action, nType, nVersion);
        READWRITE(regTxId);
        READWRITE(newPubKey);
        READWRITE(lastPubkeySig);
    }
};

class CSubTxClose : public CSubTxDataExistingUser {
private:
    std::vector<unsigned char> lastPubkeySig;

public:
    CSubTxClose() : CSubTxDataExistingUser(SubTxAction_Close) {}
    CSubTxClose(const uint256 &_regTxId) : CSubTxDataExistingUser(SubTxAction_Close, _regTxId) {}

    virtual bool Check(const CTransaction &subTx, CEvoUser &user, CValidationState &state) override;
    virtual bool Process(const CTransaction &subTx, CEvoUser &user, CValidationState &state) override;
    virtual bool Undo(const CTransaction &subTx, CEvoUser &user, CValidationState &state) override;

    std::string MakeSignMessage() const;
    bool Sign(const CKey &key);

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        BaseSerializationOp(s, ser_action, nType, nVersion);
        READWRITE(regTxId);
        READWRITE(lastPubkeySig);
    }
};

#endif //DASH_SUBTX_H
