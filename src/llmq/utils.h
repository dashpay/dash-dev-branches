// Copyright (c) 2018-2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LLMQ_UTILS_H
#define BITCOIN_LLMQ_UTILS_H

#include <llmq/params.h>
#include <set>
#include <sync.h>
#include <gsl/pointers.h>
#include <uint256.h>

#include <map>
#include <optional>
#include <vector>

class CConnman;
class CBlockIndex;
class CDeterministicMN;
class CDeterministicMNList;
using CDeterministicMNCPtr = std::shared_ptr<const CDeterministicMN>;

namespace llmq
{

class CQuorumManager;
class CQuorumSnapshot;

namespace utils
{

// includes members which failed DKG
std::vector<CDeterministicMNCPtr> GetAllQuorumMembers(Consensus::LLMQType llmqType, gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, bool reset_cache = false);

uint256 DeterministicOutboundConnection(const uint256& proTxHash1, const uint256& proTxHash2);
std::set<uint256> GetQuorumConnections(const Consensus::LLMQParams& llmqParams, gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, const uint256& forMember, bool onlyOutbound);
std::set<uint256> GetQuorumRelayMembers(const Consensus::LLMQParams& llmqParams, gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, const uint256& forMember, bool onlyOutbound);
std::set<size_t> CalcDeterministicWatchConnections(Consensus::LLMQType llmqType, gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, size_t memberCount, size_t connectionCount);

bool EnsureQuorumConnections(const Consensus::LLMQParams& llmqParams, gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, CConnman& connman, const uint256& myProTxHash);
void AddQuorumProbeConnections(const Consensus::LLMQParams& llmqParams, gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, CConnman& connman, const uint256& myProTxHash);

bool IsQuorumTypeEnabled(Consensus::LLMQType llmqType, const CQuorumManager& qman, gsl::not_null<const CBlockIndex*> pindexPrev);
bool IsQuorumTypeEnabledInternal(Consensus::LLMQType llmqType, const CQuorumManager& qman, gsl::not_null<const CBlockIndex*> pindexPrev, std::optional<bool> optDIP0024IsActive, std::optional<bool> optHaveDIP0024Quorums);

std::vector<Consensus::LLMQType> GetEnabledQuorumTypes(gsl::not_null<const CBlockIndex*> pindex);
std::vector<std::reference_wrapper<const Consensus::LLMQParams>> GetEnabledQuorumParams(gsl::not_null<const CBlockIndex*> pindex);

template <typename CacheType>
void InitQuorumsCache(CacheType& cache, bool limit_by_connections = true);

} // namespace utils

} // namespace llmq

#endif // BITCOIN_LLMQ_UTILS_H
