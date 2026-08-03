// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstate.h>

#include <chain.h>
#include <coins.h>
#include <chainparamsbase.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <sync.h>
#include <threadsafety.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/translation.h>
#include <validation.h>

#include <bls/bls.h>
#include <evo/chainhelper.h>
#include <evo/deterministicmns.h>
#include <evo/evodb.h>
#include <evo/mnhftx.h>
#include <gsl/pointers.h>
#include <llmq/context.h>

#include <atomic>
#include <cassert>
#include <memory>
#include <vector>

namespace node {
ChainstateLoadResult LoadChainstate(ChainstateManager& chainman, const CacheSizes& cache_sizes,
                                    const ChainstateLoadOptions& options, std::unique_ptr<CEvoDB>& evodb,
                                    std::unique_ptr<CDeterministicMNManager>& dmnman, std::unique_ptr<LLMQContext>& llmq_ctx,
                                    std::unique_ptr<CChainstateHelper>& chain_helper)
{
    assert(options.mn_metaman);
    assert(options.sporkman);
    assert(options.chainlocks);
    assert(options.mn_sync);

    const bool to_wipe_data = options.reindex || options.reindex_chainstate;
    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return to_wipe_data || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    LOCK(cs_main);

    evodb.reset();
    // TODO: pass DbWrapperParams as options instead multiple params
    evodb = std::make_unique<CEvoDB>(util::DbWrapperParams{.path = options.data_dir, .memory = options.dash_dbs_in_memory, .wipe = to_wipe_data});

    dmnman.reset();
    dmnman = std::make_unique<CDeterministicMNManager>(*evodb, *options.mn_metaman);

    chainman.m_total_coinstip_cache = cache_sizes.coins;
    chainman.m_total_coinsdb_cache = cache_sizes.coins_db;

    // Load the fully validated chainstate.
    chainman.InitializeChainstate(options.mempool, *evodb, chain_helper);

    // Load a chain created from a UTXO snapshot, if any exist.
    chainman.DetectSnapshotChainstate(options.mempool);

    auto& pblocktree{chainman.m_blockman.m_block_tree_db};
    // new CBlockTreeDB tries to delete the existing file, which
    // fails if it's still open from the previous loop. Close it first:
    pblocktree.reset();
    pblocktree.reset(new CBlockTreeDB(cache_sizes.block_tree_db, options.block_tree_db_in_memory, options.reindex));

    // Initialize llmq_ctx and connection to mempool
    llmq_ctx.reset();
    llmq_ctx = std::make_unique<LLMQContext>(*dmnman, *evodb, *options.sporkman, chainman,
                                             util::DbWrapperParams{.path = options.data_dir, .memory = options.dash_dbs_in_memory, .wipe = to_wipe_data},
                                             options.bls_threads, options.worker_count, options.max_recsigs_age);
    if (options.mempool) {
        options.mempool->ConnectManagers(dmnman.get(), llmq_ctx->isman.get());
    }

    // Initialize chain_helper
    chain_helper.reset();
    chain_helper = std::make_unique<CChainstateHelper>(*evodb, *dmnman, *options.mn_sync, *(llmq_ctx->isman), *(llmq_ctx->quorum_block_processor),
                                                       *(llmq_ctx->qsnapman), chainman, chainman.GetConsensus(), *options.chainlocks,
                                                       *(llmq_ctx->qman));

    if (options.reindex) {
        pblocktree->WriteReindexing(true);
        //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
        if (options.prune) {
            CleanupBlockRevFiles();
        }
    }

    if (options.check_interrupt && options.check_interrupt()) return {ChainstateLoadStatus::INTERRUPTED, {}};

    // LoadBlockIndex will load m_have_pruned if we've ever removed a
    // block file from disk.
    // Note that it also sets fReindex global based on the disk flag!
    // From here on, fReindex and options.reindex values may be different!
    if (!chainman.LoadBlockIndex()) {
        if (options.check_interrupt && options.check_interrupt()) return {ChainstateLoadStatus::INTERRUPTED, {}};
        return {ChainstateLoadStatus::FAILURE, _("Error loading block database")};
    }

    if (!chainman.BlockIndex().empty() &&
            !chainman.m_blockman.LookupBlockIndex(chainman.GetConsensus().hashGenesisBlock)) {
        // If the loaded chain has a wrong genesis, bail out immediately
        // (we're likely using a testnet datadir, or the other way around).
        return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Incorrect or no genesis block found. Wrong datadir for network?")};
    }

    if (!chainman.GetConsensus().hashDevnetGenesisBlock.IsNull() && !chainman.BlockIndex().empty() &&
            !chainman.m_blockman.LookupBlockIndex(chainman.GetConsensus().hashDevnetGenesisBlock)) {
        return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Incorrect or no devnet genesis block found. Wrong datadir for devnet specified?")};
    }

    // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
    // in the past, but is now trying to run unpruned.
    if (chainman.m_blockman.m_have_pruned && !options.prune) {
        return {ChainstateLoadStatus::FAILURE, _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain")};
    }

    // At this point blocktree args are consistent with what's on disk.
    // If we're not mid-reindex (based on disk + args), add a genesis block on disk
    // (otherwise we use the one already on disk).
    // This is called again in ThreadImport after the reindex completes.
    if (!fReindex && !chainman.ActiveChainstate().LoadGenesisBlock()) {
        return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
    }

    // Conservative value which is arbitrarily chosen, as it will ultimately be changed
    // by a call to `chainman.MaybeRebalanceCaches()`. We just need to make sure
    // that the sum of the two caches (40%) does not exceed the allowable amount
    // during this temporary initialization state.
    double init_cache_fraction = 0.2;

    // At this point we're either in reindex or we've loaded a useful
    // block tree into BlockIndex()!

    for (Chainstate* chainstate : chainman.GetAll()) {
        LogPrintf("Initializing chainstate %s\n", chainstate->ToString());

        chainstate->InitCoinsDB(
            /*cache_size_bytes=*/chainman.m_total_coinsdb_cache * init_cache_fraction,
            /*in_memory=*/options.coins_db_in_memory,
            /*should_wipe=*/options.reindex || options.reindex_chainstate);

        if (options.coins_error_cb) {
            chainstate->CoinsErrorCatcher().AddReadErrCallback(options.coins_error_cb);
        }

        // Refuse to load unsupported database format.
        // This is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        if (chainstate->CoinsDB().NeedsUpgrade()) {
            return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Unsupported chainstate database format found. "
                                                                     "Please restart with -reindex-chainstate. This will "
                                                                     "rebuild the chainstate database.")};
        }

        // ReplayBlocks is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        if (!chainstate->ReplayBlocks()) {
            return {ChainstateLoadStatus::FAILURE, _("Unable to replay blocks. You will need to rebuild the database using -reindex-chainstate.")};
        }

        // The on-disk coinsdb is now in a good state, create the cache
        chainstate->InitCoinsCache(chainman.m_total_coinstip_cache * init_cache_fraction);
        assert(chainstate->CanFlushToDisk());

        // flush evodb
        // TODO: CEvoDB instance should probably be a part of Chainstate
        // (for multiple chainstates to actually work in parallel)
        // and not a global
        if (&chainman.ActiveChainstate() == chainstate && !evodb->CommitRootTransaction()) {
            return {ChainstateLoadStatus::FAILURE, _("Failed to commit Evo database")};
        }

        if (!is_coinsview_empty(chainstate)) {
            // LoadChainTip initializes the chain based on CoinsTip()'s best block
            if (!chainstate->LoadChainTip()) {
                return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
            }
            assert(chainstate->m_chain.Tip() != nullptr);
        }
    }

    if (!chain_helper->ehf_manager->ForceSignalDBUpdate()) {
        return {ChainstateLoadStatus::FAILURE, _("Error upgrading evo database for EHF")};
    }

    // Check if nVersion-first migration is needed and perform it
    if (dmnman->IsMigrationRequired() && !dmnman->MigrateLegacyDiffs(chainman.ActiveChainstate().m_chain.Tip())) {
        return {ChainstateLoadStatus::FAILURE, _("Failed to upgrade Evo database")};
    }

    // Now that chainstates are loaded and we're able to flush to
    // disk, rebalance the coins caches to desired levels based
    // on the condition of each chainstate.
    chainman.MaybeRebalanceCaches();

    return {ChainstateLoadStatus::SUCCESS, {}};
}

ChainstateLoadResult VerifyLoadedChainstate(ChainstateManager& chainman, const ChainstateLoadOptions& options, CEvoDB& evodb,
                                            std::function<void(bool)> notify_bls_state)
{
    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return options.reindex || options.reindex_chainstate || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    LOCK(cs_main);

    for (Chainstate* chainstate : chainman.GetAll()) {
        if (!is_coinsview_empty(chainstate)) {
            const CBlockIndex* tip = chainstate->m_chain.Tip();
            if (tip && tip->nTime > GetTime() + MAX_FUTURE_BLOCK_TIME) {
                return {ChainstateLoadStatus::FAILURE, _("The block database contains a block which appears to be from the future. "
                                                         "This may be due to your computer's date and time being set incorrectly. "
                                                         "Only rebuild the block database if you are sure that your computer's date and time are correct")};
            }
            const bool v19active{DeploymentActiveAfter(tip, chainman, Consensus::DEPLOYMENT_V19)};
            if (v19active) {
                bls::bls_legacy_scheme.store(false);
                // TODO: remove notify_bls_state, it's alien and irrelevant once v19 activated
                if (notify_bls_state) notify_bls_state(bls::bls_legacy_scheme.load());
            }

            if (!CVerifyDB().VerifyDB(
                    *chainstate, chainman.GetConsensus(), chainstate->CoinsDB(),
                    evodb,
                    options.check_level,
                    options.check_blocks)) {
                return {ChainstateLoadStatus::FAILURE, _("Corrupted block database detected")};
            }

            // VerifyDB() disconnects blocks which might result in us switching back to legacy.
            // Make sure we use the right scheme.
            if (v19active && bls::bls_legacy_scheme.load()) {
                bls::bls_legacy_scheme.store(false);
                if (notify_bls_state) notify_bls_state(bls::bls_legacy_scheme.load());
            }

            if (options.check_level >= 3) {
                chainstate->ResetBlockFailureFlags(nullptr);
            }

        } else {
            // TODO: CEvoDB instance should probably be a part of Chainstate
            // (for multiple chainstates to actually work in parallel)
            // and not a global
            if (&chainman.ActiveChainstate() == chainstate && !evodb.IsEmpty()) {
                // EvoDB processed some blocks earlier but we have no blocks anymore, something is wrong
                return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
            }
        }
    }

    return {ChainstateLoadStatus::SUCCESS, {}};
}
} // namespace node
