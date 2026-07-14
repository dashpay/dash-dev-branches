// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_CHAINSTATE_H
#define BITCOIN_NODE_CHAINSTATE_H

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <validation.h>

class CChainstateHelper;
class CDeterministicMNManager;
class CEvoDB;
class ChainstateManager;
class CMasternodeSync;
class CMasternodeMetaMan;
class CSporkManager;
class CTxMemPool;
struct LLMQContext;

namespace chainlock { class Chainlocks; }
namespace fs {
class path;
} // namespace fs

namespace node {
struct CacheSizes;

struct ChainstateLoadOptions {
    CTxMemPool* mempool{nullptr};
    bool block_tree_db_in_memory{false};
    bool coins_db_in_memory{false};
    bool dash_dbs_in_memory{false};
    bool reindex{false};
    bool reindex_chainstate{false};
    bool prune{false};
    int8_t bls_threads{0};
    int16_t worker_count{0};
    int64_t max_recsigs_age{0};
    int64_t check_blocks{DEFAULT_CHECKBLOCKS};
    int64_t check_level{DEFAULT_CHECKLEVEL};
    std::function<bool()> check_interrupt;
    std::function<void()> coins_error_cb;
    std::function<void(bool)> notify_bls_state;
};

//! Chainstate load status. Simple applications can just check for the success
//! case, and treat other cases as errors. More complex applications may want to
//! try reindexing in the generic failure case, and pass an interrupt callback
//! and exit cleanly in the interrupted case.
enum class ChainstateLoadStatus { SUCCESS, FAILURE, FAILURE_INCOMPATIBLE_DB, INTERRUPTED };

//! Chainstate load status code and optional error string.
using ChainstateLoadResult = std::tuple<ChainstateLoadStatus, bilingual_str>;

/** This sequence can have 4 types of outcomes:
 *
 *  1. Success
 *  2. Shutdown requested
 *    - nothing failed but a shutdown was triggered in the middle of the
 *      sequence
 *  3. Soft failure
 *    - a failure that might be recovered from with a reindex
 *  4. Hard failure
 *    - a failure that definitively cannot be recovered from with a reindex
 *
 *  LoadChainstate returns a (status code, error string) tuple.
 */
ChainstateLoadResult LoadChainstate(ChainstateManager& chainman,
                                                     CMasternodeMetaMan& mn_metaman,
                                                     CSporkManager& sporkman,
                                                     chainlock::Chainlocks& chainlocks,
                                                     const CMasternodeSync& mn_sync,
                                                     std::unique_ptr<CChainstateHelper>& chain_helper,
                                                     std::unique_ptr<CDeterministicMNManager>& dmnman,
                                                     std::unique_ptr<CEvoDB>& evodb,
                                                     std::unique_ptr<LLMQContext>& llmq_ctx,
                                                     const fs::path& data_dir,
                                                     const CacheSizes& cache_sizes,
                                                     const ChainstateLoadOptions& options);

/** Initialize Dash-specific components during chainstate initialization */
void DashChainstateSetup(ChainstateManager& chainman,
                         CMasternodeMetaMan& mn_metaman,
                         CSporkManager& sporkman,
                         chainlock::Chainlocks& chainlocks,
                         const CMasternodeSync& mn_sync,
                         std::unique_ptr<CChainstateHelper>& chain_helper,
                         std::unique_ptr<CDeterministicMNManager>& dmnman,
                         CEvoDB& evodb,
                         std::unique_ptr<LLMQContext>& llmq_ctx,
                         CTxMemPool* mempool,
                         const fs::path& data_dir,
                         bool llmq_dbs_in_memory,
                         bool llmq_dbs_wipe,
                         int8_t bls_threads,
                         int16_t worker_count,
                         int64_t max_recsigs_age);

void DashChainstateSetupClose(std::unique_ptr<CChainstateHelper>& chain_helper,
                              std::unique_ptr<CDeterministicMNManager>& dmnman,
                              std::unique_ptr<LLMQContext>& llmq_ctx,
                              CTxMemPool* mempool);

ChainstateLoadResult VerifyLoadedChainstate(ChainstateManager& chainman, CEvoDB& evodb,
                                            const ChainstateLoadOptions& options);
} // namespace node

#endif // BITCOIN_NODE_CHAINSTATE_H
