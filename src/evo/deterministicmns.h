// Copyright (c) 2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_DETERMINISTICMNS_H
#define DASH_DETERMINISTICMNS_H

#include "providertx.h"
#include "dbwrapper.h"
#include "sync.h"
#include "spork.h"

#include <map>

#include <boost/range/adaptors.hpp>
#include <boost/range/any_range.hpp>

class CBlock;
class CBlockIndex;
class CValidationState;

class CDeterministicMNState {
public:
    int64_t registeredHeight{-1};
    int64_t lastPaidHeight{0};
    int64_t maturityHeight{-1};
    int32_t PoSePenality{0};
    int64_t PoSeRevivedHeight{-1};
    int64_t PoSeBanHeight{-1};

public:
    CDeterministicMNState() {}
    template<typename Stream>
    CDeterministicMNState(deserialize_type, Stream& s) { s >> *this;}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(registeredHeight);
        READWRITE(lastPaidHeight);
        READWRITE(maturityHeight);
        READWRITE(PoSePenality);
        READWRITE(PoSeRevivedHeight);
        READWRITE(PoSeBanHeight);
    }

    bool operator==(const CDeterministicMNState &rhs) const {
        return registeredHeight == rhs.registeredHeight &&
               lastPaidHeight == rhs.lastPaidHeight &&
               maturityHeight == rhs.maturityHeight &&
               PoSePenality == rhs.PoSePenality &&
               PoSeRevivedHeight == rhs.PoSeRevivedHeight &&
               PoSeBanHeight == rhs.PoSeBanHeight;
    }

    bool operator!=(const CDeterministicMNState &rhs) const {
        return !(rhs == *this);
    }
};
typedef std::shared_ptr<CDeterministicMNState> CDeterministicMNStatePtr;
typedef std::shared_ptr<const CDeterministicMNState> CDeterministicMNStateCPtr;

class CDeterministicMN {
public:
    uint256 proTxHash;
    CProviderTXRegisterMNCPtr proTx;
    CDeterministicMNStateCPtr state;
};
typedef std::shared_ptr<CDeterministicMN> CDeterministicMNPtr;
typedef std::shared_ptr<const CDeterministicMN> CDeterministicMNCPtr;

class CDeterministicMNListDiff;

class CDeterministicMNList {
public:
    typedef std::map<uint256, CDeterministicMNCPtr> MnMap;
    typedef std::shared_ptr<MnMap> MnMapPtr;

private:
    int64_t height{-1};
    MnMapPtr mnMap;

public:
    CDeterministicMNList() : mnMap(std::make_shared<MnMap>()) {}
    explicit CDeterministicMNList(int64_t _height, MnMapPtr _mnMap = std::make_shared<MnMap>()) :
            height(_height),
            mnMap(_mnMap)
    {}

    CDeterministicMNList Clone() const {
        MnMapPtr newMnMap = std::make_shared<MnMap>(mnMap->begin(), mnMap->end());
        return CDeterministicMNList(height, newMnMap);
    }

    // we don't serialize the ProTx (would result in too much duplicate data)
    template<typename Stream>
    void Serialize(Stream& s) const {
        s << height;
        s << (int32_t)mnMap->size();
        for (const auto &p : *mnMap) {
            s << p.first;
            s << p.second->state;
        }
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        mnMap = std::make_shared<MnMap>();

        s >> height;
        int32_t size;
        s >> size;
        for (int32_t i = 0; i < size; i++) {
            CDeterministicMNPtr dmn = std::make_shared<CDeterministicMN>();
            s >> dmn->proTxHash;
            s >> dmn->state;

            mnMap->emplace(dmn->proTxHash, dmn);
        }
    }

public:

    size_t size() const {
        return mnMap->size();
    }

    typedef boost::any_range<const CDeterministicMNCPtr&, boost::forward_traversal_tag> range_type;

    range_type all_range() const {
        return boost::adaptors::transform(*mnMap, [] (const MnMap::value_type &p) -> const CDeterministicMNCPtr& {
            return p.second;
        });
    }

    range_type valid_range() const {
        return boost::adaptors::filter(all_range(), [&] (const CDeterministicMNCPtr &dmn) -> bool {
            return IsMNValid(dmn);
        });
    }

    size_t all_count() const {
        return mnMap->size();
    }

    size_t valid_count() const {
        size_t c = 0;
        for (const auto &p : *mnMap) {
            if (IsMNValid(p.second)) {
                c++;
            }
        }
        return c;
    }

public:
    int64_t GetHeight() const {
        return height;
    }
    void SetHeight(int64_t _height) {
        height = _height;
    }
    MnMapPtr GetMap() {
        return mnMap;
    }

    bool IsMNValid(const uint256 &proTxHash) const;
    bool IsMNMature(const uint256 &proTxHash) const;
    bool IsMNPoSeBanned(const uint256 &proTxHash) const;

    bool HasMN(const uint256 &proTxHash) const {
        return GetMN(proTxHash) != nullptr;
    }
    CDeterministicMNCPtr GetMN(const uint256 &proTxHash) const;
    CDeterministicMNCPtr GetValidMN(const uint256 &proTxHash) const;
    CDeterministicMNCPtr GetMNByMasternodeKey(const CKeyID &keyIDMasternode);
    CDeterministicMNCPtr GetMNPayee() const;

    void BuildDiff(const CDeterministicMNList &to, CDeterministicMNListDiff &diffRet) const;
    CDeterministicMNList ApplyDiff(const CDeterministicMNListDiff &diff, const std::map<uint256, CProviderTXRegisterMNCPtr> &proTxMap) const;

    void AddOrUpdateMN(const CDeterministicMN &dmn) {
        auto p = std::make_shared<CDeterministicMN>(dmn);
        auto i = mnMap->emplace(dmn.proTxHash, p);
        if (!i.second)
            i.first->second = p;
    }
    void RemoveMN(const uint256 &proTxHash) {
        mnMap->erase(proTxHash);
    }
    void AddOrUpdateMN(const uint256 &proTxHash, const CDeterministicMNStateCPtr &state, const CProviderTXRegisterMNCPtr &proTx) {
        auto dmnPtr = GetMN(proTxHash);
        CDeterministicMN dmn;
        if (dmnPtr) {
            dmn = *dmnPtr;
        } else {
            dmn.proTxHash = proTxHash;
        }
        if (state) {
            dmn.state = state;
        }
        if (proTx) {
            dmn.proTx = proTx;
        }
        AddOrUpdateMN(dmn);
    }

private:
    bool IsMNValid(const CDeterministicMNCPtr &dmn) const;
    bool IsMNMature(const CDeterministicMNCPtr &dmn) const;
    bool IsMNPoSeBanned(const CDeterministicMNCPtr &dmn) const;
};

class CDeterministicMNListDiff {
public:
    int64_t height;
    std::map<uint256, CDeterministicMNStateCPtr> addedOrUpdatedMns;
    std::set<uint256> removedMns;

public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(height);
        READWRITE(addedOrUpdatedMns);
        READWRITE(removedMns);
    }

public:
    bool HasChanges() const {
        return !addedOrUpdatedMns.empty() || !removedMns.empty();
    }
};

class CDeterministicMNManagerState {
public:
    int64_t firstMNHeight{-1};
    int64_t curHeight{0};
    uint256 curBlockHash;
    int64_t spork15Value{SPORK_15_DETERMINISTIC_MNS_DEFAULT};

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(firstMNHeight);
        READWRITE(curHeight);
        READWRITE(curBlockHash);
        READWRITE(spork15Value);
    }
};

class CDeterministicMNManager {
    static const int SNAPSHOT_LIST_PERIOD = 576; // once per day
    static const int LISTS_CACHE_SIZE = 576;

private:
    CCriticalSection cs;

    CDBWrapper db;
    CDBTransaction dbTransaction;

    CDeterministicMNManagerState state;
    CDeterministicMNManagerState stateBackup; // for rollback

    // stores a list per block.
    // Mutliple consecutive entries might internally point to the same list in case nothing changed in a block
    std::map<int64_t, CDeterministicMNList> lists;
    std::map<int64_t, CDeterministicMNList> listsBackup; // for rollback

    std::map<uint256, std::weak_ptr<const CProviderTXRegisterMN>> proTxCache;

public:
    CDeterministicMNManager(size_t nCacheSize, bool fMemory=false, bool fWipe=false);

    std::unique_ptr<CScopedDBTransaction> BeginTransaction() {
        LOCK(cs);
        stateBackup = state;
        listsBackup = lists;
        auto t = CScopedDBTransaction::Begin(dbTransaction);
        t->SetRollbackHandler([&] {
            state = stateBackup;
            lists.swap(listsBackup);
            listsBackup.clear();
        });
        t->SetCommitHandler([&] {
            listsBackup.clear();
        });
        return t;
    }

    void Init();

    bool ProcessBlock(const CBlock &block, const CBlockIndex *pindex, CValidationState &state);
    bool UndoBlock(const CBlock &block, const CBlockIndex *pindex);

    CProviderTXRegisterMNCPtr GetProTx(const uint256 &proTxHash);

    CDeterministicMNList GetListAtHeight(int64_t height);
    CDeterministicMNList GetListAtChainTip();

    CDeterministicMNCPtr GetMN(int64_t height, const uint256 &proTxHash);
    bool HasValidMNAtHeight(int64_t height, const uint256 &proTxHash);
    bool HasValidMNAtChainTip(const uint256 &proTxHash);

    bool IsDeterministicMNsSporkActive(int64_t height = -1);

private:
    void UpdateSpork15Value();
    void RebuildLists(int64_t startHeight, int64_t endHeight);
};

extern CDeterministicMNManager *deterministicMNManager;

#endif//DASH_DETERMINISTICMNS_H