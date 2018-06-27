// Copyright (c) 2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "graphene.h"
#include "chainparams.h"
//#include "connmgr.h"
#include "consensus/merkle.h"
//#include "dosman.h"
//#include "expedited.h"
#include "net.h"
#include "net_processing.h"
#include "netmessagemaker.h"
//#include "parallel.h"
#include "policy/policy.h"
#include "pow.h"
//#include "requestManager.h"
#include "timedata.h"
#include "txmempool.h"
//#include "txorphanpool.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"

//static bool ReconstructBlock(CNode *pfrom, const bool fXVal, int &missingCount, int &unnecessaryCount);

CMemPoolInfo::CMemPoolInfo(uint64_t nTx) { this->nTx = nTx; }
CMemPoolInfo::CMemPoolInfo() { this->nTx = 0; }
CGrapheneBlock::CGrapheneBlock(const CBlockRef pblock, uint64_t nReceiverMemPoolTx)
{
    header = pblock->GetBlockHeader();
    nBlockTxs = pblock->vtx.size();

    std::vector<uint256> blockHashes;
    for (auto &tx : pblock->vtx)
    {
        blockHashes.push_back(tx->GetHash());

        if (tx->IsCoinBase())
            vAdditionalTxs.push_back(tx);

        // Adding mempool bloom filter in Graphene block, add transactions that weren't in the mempool
        // b*loom filter of the sender.
        // if (!senderMempoolFilter.contains(tx->GetHash()))
        //     vAdditionalTxs.push_back(tx);
    }

    pGrapheneSet = new CGrapheneSet(nReceiverMemPoolTx, blockHashes, true);


}

CGrapheneBlock::~CGrapheneBlock()
{
    if (pGrapheneSet)
    {
        delete pGrapheneSet;
        pGrapheneSet = nullptr;
    }
}

CGrapheneBlockTx::CGrapheneBlockTx(uint256 blockHash, std::vector<CMutableTransaction> &vTx)
{
    blockhash = blockHash;
    vMissingTx = vTx;
}


CRequestGrapheneBlockTx::CRequestGrapheneBlockTx(uint256 blockHash, std::set<uint64_t> &setHashesToRequest)
{
    blockhash = blockHash;
    setCheapHashesToRequest = setHashesToRequest;
}



bool CGrapheneBlock::CheckBlockHeader(const CBlockHeader &block, CValidationState &state)
{
    // Check proof of work matches claimed amount
    if (!CheckProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus()))
        return state.DoS(50, error("CheckBlockHeader(): proof of work failed"), REJECT_INVALID, "high-hash");

    // Check timestamp
    if (header.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(
            error("CheckBlockHeader(): block timestamp too far in the future"), REJECT_INVALID, "time-too-new");

    return true;
}



// TODO: PushMessage, CConnman
// TODO: request from the "best" txn source not necessarily from the block source
bool CGrapheneBlock::process(CNode *pfrom, int nSizeGrapheneBlock, std::string strCommand, CConnman& connman)
{
    CNetMsgMaker msgMaker(PROTOCOL_VERSION);
    // In PV we must prevent two graphene blocks from simulaneously processing from that were recieved from the
    // same peer. This would only happen as in the example of an expedited block coming in
    // after an graphene request, because we would never explicitly request two graphene blocks from the same peer.
    // if (PV->IsAlreadyValidating(pfrom->id) return false;

    // Xpress Validation - only perform xval if the chaintip matches the last blockhash in the graphene block
    bool fXVal;
    {
        LOCK(cs_main);
        fXVal = (header.hashPrevBlock == chainActive.Tip()->GetBlockHash()) ? true : false;
    }

    graphenedata.ClearGrapheneBlockData(pfrom);
    pfrom->nSizeGrapheneBlock = nSizeGrapheneBlock;

    uint256 nullhash;
    pfrom->grapheneBlock.nVersion = header.nVersion;
    pfrom->grapheneBlock.nBits = header.nBits;
    pfrom->grapheneBlock.nNonce = header.nNonce;
    pfrom->grapheneBlock.nTime = header.nTime;
    pfrom->grapheneBlock.hashMerkleRoot = header.hashMerkleRoot;
    pfrom->grapheneBlock.hashPrevBlock = header.hashPrevBlock;
    pfrom->grapheneBlockHashes.clear();
    pfrom->grapheneBlockHashes.resize(nBlockTxs, nullhash);

    {
        LOCK(pfrom->cs_grapheneadditionaltxs);

        pfrom->grapheneAdditionalTxs.clear();
        for (auto tx : vAdditionalTxs)
            pfrom->grapheneAdditionalTxs.push_back(tx);
    }

    vTxHashes.reserve(nBlockTxs);

    // Create a map of all 8 bytes tx hashes pointing to their full tx hash counterpart
    // We need to check all transaction sources (orphan list, mempool, and new (incoming) transactions in this block)
    // for a collision.
    int missingCount = 0;
    int unnecessaryCount = 0;
    bool collision = false;
    std::set<uint256> passingTxHashes;
    std::map<uint64_t, uint256> mapPartialTxHash;
    std::vector<uint256> memPoolHashes;
    std::set<uint64_t> setHashesToRequest;

    bool fMerkleRootCorrect = true;
    {
        //TODO: Orphan Transactions better solution
        // Do the orphans first before taking the mempool.cs lock, so that we maintain correct locking order.
        LOCK(cs_main);
//        for (auto &kv : mapOrphanTransactions)
//        {
//            uint256 hash = kv.first;
//
//            uint64_t cheapHash = hash.GetCheapHash();
//
//            if (mapPartialTxHash.count(cheapHash)) // Check for collisions
//                collision = true;
//
//            mapPartialTxHash[cheapHash] = hash;
//        }

        // We don't have to keep the lock on mempool.cs here to do mempool.queryHashes
        // but we take the lock anyway so we don't have to re-lock again later.
        ////////////////////// What is cs_xval for?
        // TODO cs_xval
        LOCK(cs_main);
        mempool.queryHashes(memPoolHashes);

        for (const uint256 &hash : memPoolHashes)
        {
            uint64_t cheapHash = hash.GetCheapHash();

            if (mapPartialTxHash.count(cheapHash)) // Check for collisions
                collision = true;

            mapPartialTxHash[cheapHash] = hash;
        }

        if (!collision)
        {
            std::vector<uint256> localHashes;
            for (const std::pair<uint64_t, uint256> &kv : mapPartialTxHash)
                localHashes.push_back(kv.second);

            // Add full transactions included in the block
            for (auto tx : vAdditionalTxs)
                localHashes.push_back(tx->GetHash());

            try
            {
                std::vector<uint64_t> blockCheapHashes = pGrapheneSet->Reconcile(localHashes);

                // Sort out what hashes we have from the complete set of cheapHashes
                uint64_t nGrapheneTxsPossessed = 0;
                for (size_t i = 0; i < blockCheapHashes.size(); i++)
                {
                    uint64_t cheapHash = blockCheapHashes[i];

                    if (mapPartialTxHash.count(cheapHash) > 0)
                    {
                        pfrom->grapheneBlockHashes[i] = mapPartialTxHash[cheapHash];

                        // Update mapHashOrderIndex so it is available if we later receive missing txs
                        pfrom->grapheneMapHashOrderIndex[cheapHash] = i;
                        nGrapheneTxsPossessed++;
                    }
                    else
                        setHashesToRequest.insert(cheapHash);
                }

                graphenedata.AddGrapheneBlockBytes(nGrapheneTxsPossessed * sizeof(uint64_t), pfrom);
            }
            catch (std::exception &e)
            {
                return error("Graphene set could not be reconciled: requesting a full block");
            }

            // Reconstruct the block if there are no hashes to re-request
            if (setHashesToRequest.empty())
            {
                bool mutated;
                uint256 merkleroot = ComputeMerkleRoot(pfrom->grapheneBlockHashes, &mutated);
                if (header.hashMerkleRoot != merkleroot || mutated)
                    fMerkleRootCorrect = false;
                else
                {
                    // TODO: Work on reconstructBlock
//                    if (!ReconstructBlockFromGraphene(pfrom, fXVal, missingCount, unnecessaryCount))
                        return false;
                }
            }
        }
    } // End locking cs_orphancache, mempool.cs and cs_xval
    LogPrint("GRAPHENE", "Total in-memory graphene bytes size is %ld bytes\n", graphenedata.GetGrapheneBlockBytes());

    // These must be checked outside of the mempool.cs lock or deadlock may occur.
    // A merkle root mismatch here does not cause a ban because and expedited node will forward an graphene
    // without checking the merkle root, therefore we don't want to ban our expedited nodes. Just re-request
    // a full graphene block if a mismatch occurs.
    // Also, there is a remote possiblity of a Tx hash collision therefore if it occurs we re-request a normal
    // graphene block which has the full Tx hash data rather than just the truncated hash.
    //////////////// Maybe this should raise a ban in graphene? /////////////
    if (collision || !fMerkleRootCorrect)
    {
        std::vector<CInv> vGetData;
        vGetData.push_back(CInv(MSG_GRAPHENE_BLOCK, header.GetHash()));
        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vGetData));

        if (!fMerkleRootCorrect)
            return error("Mismatched merkle root on grapheneblock: rerequesting a graphene block, peer=%d", pfrom->id);
        else
            return error("TX HASH COLLISION for grapheneblock: re-requesting a graphene block, peer=%d", pfrom->id);

        graphenedata.ClearGrapheneBlockData(pfrom, header.GetHash());
        return true;
    }

    pfrom->grapheneBlockWaitingForTxns = missingCount;
    LogPrint("GRAPHENE", "Graphene block waiting for: %d, unnecessary: %d, total txns: %d received txns: %d\n",
             pfrom->grapheneBlockWaitingForTxns, unnecessaryCount, pfrom->grapheneBlock.vtx.size(),
             pfrom->mapMissingTx.size());

    // If there are any missing hashes or transactions then we request them here.
    // This must be done outside of the mempool.cs lock or may deadlock.
    if (setHashesToRequest.size() > 0)
    {
        pfrom->grapheneBlockWaitingForTxns = setHashesToRequest.size();
        CRequestGrapheneBlockTx grapheneBlockTx(header.GetHash(), setHashesToRequest);
        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETGRAPHENETX, grapheneBlockTx));

        // Update run-time statistics of graphene block bandwidth savings
        graphenedata.UpdateInBoundReRequestedTx(pfrom->grapheneBlockWaitingForTxns);

        return true;
    }

    // If there are still any missing transactions then we must clear out the graphene block data
    // and re-request a full block (This should never happen because we just checked the various pools).
    if (missingCount > 0)
    {
        // Since we can't process this graphene block then clear out the data from memory
        graphenedata.ClearGrapheneBlockData(pfrom, header.GetHash());

        std::vector<CInv> vGetData;
        vGetData.push_back(CInv(MSG_BLOCK, header.GetHash()));
        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vGetData));

        return error("Still missing transactions for graphene block: re-requesting a full block");
    }

    // We now have all the transactions that are in this block
    pfrom->grapheneBlockWaitingForTxns = -1;
    // TODO: CURRENT_VERSION -> BASE_VERSION, CBLOCK::BASE_VERSION, changing to PROTOCOL_VERSION for compilation
    int blockSize = ::GetSerializeSize(pfrom->grapheneBlock, SER_NETWORK, PROTOCOL_VERSION);
    LogPrint("GRAPHENE",
             "Reassembled graphene block for %s (%d bytes). Message was %d bytes, compression ratio %3.2f, peer=%d\n",
             pfrom->grapheneBlock.GetHash().ToString(), blockSize, pfrom->nSizeGrapheneBlock,
             ((float)blockSize) / ((float)pfrom->nSizeGrapheneBlock), pfrom->id);

    // Update run-time statistics of graphene block bandwidth savings
    graphenedata.UpdateInBound(pfrom->nSizeGrapheneBlock, blockSize);
    LogPrint("GRAPHENE", "Graphene block stats: %s\n", graphenedata.ToString().c_str());

    // Process the full block
    // TODO: Nakul Handle Block Message
    //  PV->HandleBlockMessage(pfrom, strCommand, MakeBlockRef(pfrom->grapheneBlock), GetInv());

    return true;
}


template <class T>
void CGrapheneBlockData::expireStats(std::map<int64_t, T> &statsMap)
{
    AssertLockHeld(cs_graphenestats);
    // Delete any entries that are more than 24 hours old
    int64_t nTimeCutoff = getTimeForStats() - 60 * 60 * 24 * 1000;

    typename std::map<int64_t, T>::iterator iter = statsMap.begin();
    while (iter != statsMap.end())
    {
        // increment to avoid iterator becoming invalid when erasing below
        typename std::map<int64_t, T>::iterator mi = iter++;

        if (mi->first < nTimeCutoff)
            statsMap.erase(mi);
    }
}

template <class T>
void CGrapheneBlockData::updateStats(std::map<int64_t, T> &statsMap, T value)
{
    AssertLockHeld(cs_graphenestats);
    statsMap[getTimeForStats()] = value;
    expireStats(statsMap);
}

/**
   Calculate average of values in map. Return 0 for no entries.
   Expires values before calculation. */
double CGrapheneBlockData::average(std::map<int64_t, uint64_t> &map)
{
    AssertLockHeld(cs_graphenestats);

    expireStats(map);

    if (map.size() == 0)
        return 0.0;

    uint64_t accum = 0U;
    for (std::pair<int64_t, uint64_t> p : map)
    {
        // avoid wraparounds
        accum = std::max(accum, accum + p.second);
    }
    return (double)accum / map.size();
}

void CGrapheneBlockData::UpdateInBound(uint64_t nGrapheneBlockSize, uint64_t nOriginalBlockSize)
{
    LOCK(cs_graphenestats);
    // Update InBound graphene block tracking information
    nOriginalSize += nOriginalBlockSize;
    nGrapheneSize += nGrapheneBlockSize;
    nBlocks += 1;
    updateStats(mapGrapheneBlocksInBound, std::pair<uint64_t, uint64_t>(nGrapheneBlockSize, nOriginalBlockSize));
}

void CGrapheneBlockData::UpdateOutBound(uint64_t nGrapheneBlockSize, uint64_t nOriginalBlockSize)
{
    LOCK(cs_graphenestats);
    nOriginalSize += nOriginalBlockSize;
    nGrapheneSize += nGrapheneBlockSize;
    nBlocks += 1;
    updateStats(mapGrapheneBlocksOutBound, std::pair<uint64_t, uint64_t>(nGrapheneBlockSize, nOriginalBlockSize));
}

void CGrapheneBlockData::UpdateOutBoundMemPoolInfo(uint64_t nMemPoolInfoSize)
{
    LOCK(cs_graphenestats);
    nTotalMemPoolInfoBytes += nMemPoolInfoSize;
    updateStats(mapMemPoolInfoOutBound, nMemPoolInfoSize);
}

void CGrapheneBlockData::UpdateInBoundMemPoolInfo(uint64_t nMemPoolInfoSize)
{
    LOCK(cs_graphenestats);
    nTotalMemPoolInfoBytes += nMemPoolInfoSize;
    updateStats(mapMemPoolInfoInBound, nMemPoolInfoSize);
}

void CGrapheneBlockData::UpdateFilter(uint64_t nFilterSize)
{
    LOCK(cs_graphenestats);
    nTotalFilterBytes += nFilterSize;
    updateStats(mapFilter, nFilterSize);
}

void CGrapheneBlockData::UpdateIblt(uint64_t nIbltSize)
{
    LOCK(cs_graphenestats);
    nTotalIbltBytes += nIbltSize;
    updateStats(mapIblt, nIbltSize);
}

void CGrapheneBlockData::UpdateRank(uint64_t nRankSize)
{
    LOCK(cs_graphenestats);
    nTotalRankBytes += nRankSize;
    updateStats(mapRank, nRankSize);
}

void CGrapheneBlockData::UpdateGrapheneBlock(uint64_t nGrapheneBlockSize)
{
    LOCK(cs_graphenestats);
    nTotalGrapheneBlockBytes += nGrapheneBlockSize;
    updateStats(mapGrapheneBlock, nGrapheneBlockSize);
}

void CGrapheneBlockData::UpdateAdditionalTx(uint64_t nAdditionalTxSize)
{
    LOCK(cs_graphenestats);
    nTotalAdditionalTxBytes += nAdditionalTxSize;
    updateStats(mapAdditionalTx, nAdditionalTxSize);
}

//void CGrapheneBlockData::UpdateResponseTime(double nResponseTime)
//{
//    LOCK(cs_graphenestats);
//
//    // only update stats if IBD is complete
//    if (IsChainNearlySyncd() && IsGrapheneBlockEnabled())
//        updateStats(mapGrapheneBlockResponseTime, nResponseTime);
//}

//void CGrapheneBlockData::UpdateValidationTime(double nValidationTime)
//{
//    LOCK(cs_graphenestats);
//
//    // only update stats if IBD is complete
//    if (IsChainNearlySyncd() && IsGrapheneBlockEnabled())
//        updateStats(mapGrapheneBlockValidationTime, nValidationTime);
//}

void CGrapheneBlockData::UpdateInBoundReRequestedTx(int nReRequestedTx)
{
    LOCK(cs_graphenestats);

    // Update InBound graphene block tracking information
    updateStats(mapGrapheneBlocksInBoundReRequestedTx, nReRequestedTx);
}

void CGrapheneBlockData::UpdateMempoolLimiterBytesSaved(unsigned int nBytesSaved)
{
    LOCK(cs_graphenestats);
    nMempoolLimiterBytesSaved += nBytesSaved;
}

std::string CGrapheneBlockData::ToString()
{
    LOCK(cs_graphenestats);
    double size = double(nOriginalSize() - nGrapheneSize() - nTotalMemPoolInfoBytes());
    std::ostringstream ss;
    ss << nBlocks() << " graphene " << ((nBlocks() > 1) ? "blocks have" : "block has") << " saved "
       << formatInfoUnit(size) << " of bandwidth";

    return ss.str();
}

// Calculate the graphene percentage compression over the last 24 hours
std::string CGrapheneBlockData::InBoundPercentToString()
{
    LOCK(cs_graphenestats);

    expireStats(mapGrapheneBlocksInBound);

    double nCompressionRate = 0;
    uint64_t nGrapheneSizeTotal = 0;
    uint64_t nOriginalSizeTotal = 0;
    for (std::map<int64_t, std::pair<uint64_t, uint64_t> >::iterator mi = mapGrapheneBlocksInBound.begin();
         mi != mapGrapheneBlocksInBound.end(); ++mi)
    {
        nGrapheneSizeTotal += (*mi).second.first;
        nOriginalSizeTotal += (*mi).second.second;
    }
    // We count up the outbound CMemPoolInfo sizes. Outbound CMemPoolInfo sizes go with Inbound graphene blocks.
    uint64_t nOutBoundMemPoolInfoSize = 0;
    for (std::map<int64_t, uint64_t>::iterator mi = mapMemPoolInfoOutBound.begin(); mi != mapMemPoolInfoOutBound.end();
         ++mi)
    {
        nOutBoundMemPoolInfoSize += (*mi).second;
    }

    if (nOriginalSizeTotal > 0)
        nCompressionRate = 100 - (100 * (double)(nGrapheneSizeTotal + nOutBoundMemPoolInfoSize) / nOriginalSizeTotal);

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Compression for " << mapGrapheneBlocksInBound.size()
       << " Inbound  graphene blocks (last 24hrs): " << nCompressionRate << "%";

    return ss.str();
}

// Calculate the graphene percentage compression over the last 24 hours
std::string CGrapheneBlockData::OutBoundPercentToString()
{
    LOCK(cs_graphenestats);

    expireStats(mapGrapheneBlocksOutBound);

    double nCompressionRate = 0;
    uint64_t nGrapheneSizeTotal = 0;
    uint64_t nOriginalSizeTotal = 0;
    for (std::map<int64_t, std::pair<uint64_t, uint64_t> >::iterator mi = mapGrapheneBlocksOutBound.begin();
         mi != mapGrapheneBlocksOutBound.end(); ++mi)
    {
        nGrapheneSizeTotal += (*mi).second.first;
        nOriginalSizeTotal += (*mi).second.second;
    }
    // We count up the inbound CMemPoolInfo sizes. Inbound CMemPoolInfo sizes go with Outbound graphene blocks.
    uint64_t nInBoundMemPoolInfoSize = 0;
    for (std::map<int64_t, uint64_t>::iterator mi = mapMemPoolInfoInBound.begin(); mi != mapMemPoolInfoInBound.end();
         ++mi)
        nInBoundMemPoolInfoSize += (*mi).second;

    if (nOriginalSizeTotal > 0)
        nCompressionRate = 100 - (100 * (double)(nGrapheneSizeTotal + nInBoundMemPoolInfoSize) / nOriginalSizeTotal);

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Compression for " << mapGrapheneBlocksOutBound.size()
       << " Outbound graphene blocks (last 24hrs): " << nCompressionRate << "%";
    return ss.str();
}

// Calculate the average inbound graphene CMemPoolInfo size
std::string CGrapheneBlockData::InBoundMemPoolInfoToString()
{
    LOCK(cs_graphenestats);
    double avgMemPoolInfoSize = average(mapMemPoolInfoInBound);
    std::ostringstream ss;
    ss << "Inbound CMemPoolInfo size (last 24hrs) AVG: " << formatInfoUnit(avgMemPoolInfoSize);
    return ss.str();
}

// Calculate the average outbound graphene CMemPoolInfo size
std::string CGrapheneBlockData::OutBoundMemPoolInfoToString()
{
    LOCK(cs_graphenestats);
    double avgMemPoolInfoSize = average(mapMemPoolInfoOutBound);
    std::ostringstream ss;
    ss << "Outbound CMemPoolInfo size (last 24hrs) AVG: " << formatInfoUnit(avgMemPoolInfoSize);
    return ss.str();
}

std::string CGrapheneBlockData::FilterToString()
{
    LOCK(cs_graphenestats);
    double avgFilterSize = average(mapFilter);
    std::ostringstream ss;
    ss << "Bloom filter size (last 24hrs) AVG: " << formatInfoUnit(avgFilterSize);
    return ss.str();
}

std::string CGrapheneBlockData::IbltToString()
{
    LOCK(cs_graphenestats);
    double avgIbltSize = average(mapIblt);
    std::ostringstream ss;
    ss << "IBLT size (last 24hrs) AVG: " << formatInfoUnit(avgIbltSize);
    return ss.str();
}

std::string CGrapheneBlockData::RankToString()
{
    LOCK(cs_graphenestats);
    double avgRankSize = average(mapRank);
    std::ostringstream ss;
    ss << "Rank size (last 24hrs) AVG: " << formatInfoUnit(avgRankSize);
    return ss.str();
}

std::string CGrapheneBlockData::GrapheneBlockToString()
{
    LOCK(cs_graphenestats);
    double avgGrapheneBlockSize = average(mapGrapheneBlock);
    std::ostringstream ss;
    ss << "Graphene block size (last 24hrs) AVG: " << formatInfoUnit(avgGrapheneBlockSize);
    return ss.str();
}

std::string CGrapheneBlockData::AdditionalTxToString()
{
    LOCK(cs_graphenestats);
    double avgAdditionalTxSize = average(mapAdditionalTx);
    std::ostringstream ss;
    ss << "Graphene size additional txs (last 24hrs) AVG: " << formatInfoUnit(avgAdditionalTxSize);
    return ss.str();
}

// Calculate the graphene average response time over the last 24 hours
std::string CGrapheneBlockData::ResponseTimeToString()
{
    LOCK(cs_graphenestats);

    std::vector<double> vResponseTime;

    double nResponseTimeAverage = 0;
    double nPercentile = 0;
    double nTotalResponseTime = 0;
    double nTotalEntries = 0;
    for (std::map<int64_t, double>::iterator mi = mapGrapheneBlockResponseTime.begin();
         mi != mapGrapheneBlockResponseTime.end(); ++mi)
    {
        nTotalEntries += 1;
        nTotalResponseTime += (*mi).second;
        vResponseTime.push_back((*mi).second);
    }

    if (nTotalEntries > 0)
    {
        nResponseTimeAverage = (double)nTotalResponseTime / nTotalEntries;

        // Calculate the 95th percentile
        uint64_t nPercentileElement = static_cast<int>((nTotalEntries * 0.95) + 0.5) - 1;
        sort(vResponseTime.begin(), vResponseTime.end());
        nPercentile = vResponseTime[nPercentileElement];
    }

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    ss << "Response time   (last 24hrs) AVG:" << nResponseTimeAverage << ", 95th pcntl:" << nPercentile;
    return ss.str();
}

// Calculate the graphene average block validation time over the last 24 hours
std::string CGrapheneBlockData::ValidationTimeToString()
{
    LOCK(cs_graphenestats);

    std::vector<double> vValidationTime;

    double nValidationTimeAverage = 0;
    double nPercentile = 0;
    double nTotalValidationTime = 0;
    double nTotalEntries = 0;
    for (std::map<int64_t, double>::iterator mi = mapGrapheneBlockValidationTime.begin();
         mi != mapGrapheneBlockValidationTime.end(); ++mi)
    {
        nTotalEntries += 1;
        nTotalValidationTime += (*mi).second;
        vValidationTime.push_back((*mi).second);
    }

    if (nTotalEntries > 0)
    {
        nValidationTimeAverage = (double)nTotalValidationTime / nTotalEntries;

        // Calculate the 95th percentile
        uint64_t nPercentileElement = static_cast<int>((nTotalEntries * 0.95) + 0.5) - 1;
        sort(vValidationTime.begin(), vValidationTime.end());
        nPercentile = vValidationTime[nPercentileElement];
    }

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    ss << "Validation time (last 24hrs) AVG:" << nValidationTimeAverage << ", 95th pcntl:" << nPercentile;
    return ss.str();
}

// Calculate the graphene average tx re-requested ratio over the last 24 hours
std::string CGrapheneBlockData::ReRequestedTxToString()
{
    LOCK(cs_graphenestats);

    expireStats(mapGrapheneBlocksInBoundReRequestedTx);

    double nReRequestRate = 0;
    uint64_t nTotalReRequests = 0;
    uint64_t nTotalReRequestedTxs = 0;
    for (std::map<int64_t, int>::iterator mi = mapGrapheneBlocksInBoundReRequestedTx.begin();
         mi != mapGrapheneBlocksInBoundReRequestedTx.end(); ++mi)
    {
        nTotalReRequests += 1;
        nTotalReRequestedTxs += (*mi).second;
    }

    if (mapGrapheneBlocksInBound.size() > 0)
        nReRequestRate = 100 * (double)nTotalReRequests / mapGrapheneBlocksInBound.size();

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Tx re-request rate (last 24hrs): " << nReRequestRate << "% Total re-requests:" << nTotalReRequests;
    return ss.str();
}

std::string CGrapheneBlockData::MempoolLimiterBytesSavedToString()
{
    LOCK(cs_graphenestats);
    double size = (double)nMempoolLimiterBytesSaved();
    std::ostringstream ss;
    ss << "Graphene block mempool limiting has saved " << formatInfoUnit(size) << " of bandwidth";
    return ss.str();
}

// Preferential Graphene Block Timer:
// The purpose of the timer is to ensure that we more often download an GRAPHENEBLOCK rather than a full block.
// The timer is started when we receive the first announcement indicating there is a new block to download.  If the
// block inventory is from a non GRAPHENE node then we will continue to wait for block announcements until either we
// get one from an GRAPHENE capable node or the timer is exceeded.  If the timer is exceeded before receiving an
// announcement from an GRAPHENE node then we just download a full block instead of a graphene block.
bool CGrapheneBlockData::CheckGrapheneBlockTimer(uint256 hash)
{
    LOCK(cs_mapGrapheneBlockTimer);
    if (!mapGrapheneBlockTimer.count(hash))
    {
        mapGrapheneBlockTimer[hash] = GetTimeMillis();
        LogPrint("GRAPHENE", "Starting Preferential Graphene Block timer\n");
    }
    else
    {
        // Check that we have not exceeded the 10 second limit.
        // If we have then we want to return false so that we can
        // proceed to download a regular block instead.
        uint64_t elapsed = GetTimeMillis() - mapGrapheneBlockTimer[hash];
        if (elapsed > 10000)
        {
            LogPrint("GRAPHENE", "Preferential Graphene Block timer exceeded - downloading regular block instead\n");

            return false;
        }
    }
}

// The timer is cleared as soon as we request a block or graphene block.
void CGrapheneBlockData::ClearGrapheneBlockTimer(uint256 hash)
{
    LOCK(cs_mapGrapheneBlockTimer);
    if (mapGrapheneBlockTimer.count(hash))
    {
        mapGrapheneBlockTimer.erase(hash);
        LogPrint("GRAPHENE", "Clearing Preferential Graphene Block timer\n");
    }
}

// After a graphene block is finished processing or if for some reason we have to pre-empt the rebuilding
// of a graphene block then we clear out the graphene block data which can be substantial.
void CGrapheneBlockData::ClearGrapheneBlockData(CNode *pnode)
{
    // Remove bytes from counter
    graphenedata.DeleteGrapheneBlockBytes(pnode->nLocalGrapheneBlockBytes, pnode);
    pnode->nLocalGrapheneBlockBytes = 0;

    // Clear out graphene block data we no longer need
    pnode->grapheneBlockWaitingForTxns = -1;
    pnode->grapheneBlock.SetNull();
    pnode->grapheneBlockHashes.clear();
    pnode->grapheneMapHashOrderIndex.clear();
    pnode->mapGrapheneMissingTx.clear();

    LogPrint("GRAPHENE", "Total in-memory graphene bytes size after clearing a graphene block is %ld bytes\n",
        graphenedata.GetGrapheneBlockBytes());
}

void CGrapheneBlockData::ClearGrapheneBlockData(CNode *pnode, uint256 hash)
{
    // We must make sure to clear the graphene block data first before clearing the graphene block in flight.
    ClearGrapheneBlockData(pnode);
    ClearGrapheneBlockInFlight(pnode, hash);
}

void CGrapheneBlockData::ClearGrapheneBlockStats()
{
    LOCK(cs_graphenestats);

    nOriginalSize.Clear();
    nGrapheneSize.Clear();
    nBlocks.Clear();
    nMempoolLimiterBytesSaved.Clear();
    nTotalMemPoolInfoBytes.Clear();
    nTotalFilterBytes.Clear();
    nTotalIbltBytes.Clear();
    nTotalRankBytes.Clear();
    nTotalGrapheneBlockBytes.Clear();

    mapGrapheneBlocksInBound.clear();
    mapGrapheneBlocksOutBound.clear();
    mapMemPoolInfoOutBound.clear();
    mapMemPoolInfoInBound.clear();
    mapFilter.clear();
    mapIblt.clear();
    mapRank.clear();
    mapGrapheneBlock.clear();
    mapGrapheneBlockResponseTime.clear();
    mapGrapheneBlockValidationTime.clear();
    mapGrapheneBlocksInBoundReRequestedTx.clear();
}

uint64_t CGrapheneBlockData::AddGrapheneBlockBytes(uint64_t bytes, CNode *pfrom)
{
    pfrom->nLocalGrapheneBlockBytes += bytes;
    uint64_t ret = nGrapheneBlockBytes.fetch_add(bytes) + bytes;

    return ret;
}

void CGrapheneBlockData::DeleteGrapheneBlockBytes(uint64_t bytes, CNode *pfrom)
{
    if (bytes <= pfrom->nLocalGrapheneBlockBytes)
        pfrom->nLocalGrapheneBlockBytes -= bytes;

    if (bytes <= nGrapheneBlockBytes)
        nGrapheneBlockBytes.fetch_sub(bytes);
}

void CGrapheneBlockData::ResetGrapheneBlockBytes() { nGrapheneBlockBytes.store(0); }
uint64_t CGrapheneBlockData::GetGrapheneBlockBytes() { return nGrapheneBlockBytes.load(); }

bool IsGrapheneBlockEnabled() { return GetBoolArg("-use-graphene-blocks", true); }

void SendGrapheneBlock(CBlockRef pblock, CConnman& connman, CNode *pfrom, const CInv &inv)
{
    int64_t nReceiverMemPoolTx = pfrom->nGrapheneMemPoolTx;

    // Use the size of your own mempool if receiver did not send hers
    if (nReceiverMemPoolTx == -1)
    {
        {
            LOCK(cs_main);

            nReceiverMemPoolTx = mempool.size();
        }
    }

    if (inv.type == MSG_GRAPHENE_BLOCK)
    {
        try
        {
            CGrapheneBlock grapheneBlock(MakeBlockRef(*pblock), nReceiverMemPoolTx);

            int nSizeBlock = ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION);
            int nSizeGrapheneBlock = ::GetSerializeSize(grapheneBlock, SER_NETWORK, PROTOCOL_VERSION);

            if (nSizeGrapheneBlock + MIN_MEMPOOL_INFO_BYTES >
                nSizeBlock) // If graphene block is larger than a regular block then
                // send a regular block instead
            {
                connman.PushMessage(pfrom, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::BLOCK, *pblock));
                LogPrint("GRAPHENE", "Sent regular block instead - graphene block size: %d vs block size: %d => peer: %d\n",
                         nSizeGrapheneBlock, nSizeBlock, pfrom->id);
            }
            else
            {
                graphenedata.UpdateOutBound(nSizeGrapheneBlock, nSizeBlock);
                connman.PushMessage(pfrom, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::GRAPHENEBLOCK, grapheneBlock));
                LogPrintf("GRAPHENE", "Sent graphene block - size: %d vs block size: %d => peer: %d\n", nSizeGrapheneBlock, nSizeBlock, pfrom->id);

                graphenedata.UpdateFilter(grapheneBlock.pGrapheneSet->GetFilterSerializationSize());
                graphenedata.UpdateIblt(grapheneBlock.pGrapheneSet->GetIbltSerializationSize());
                graphenedata.UpdateRank(grapheneBlock.pGrapheneSet->GetRankSerializationSize());
                graphenedata.UpdateGrapheneBlock(nSizeGrapheneBlock);
                graphenedata.UpdateAdditionalTx(grapheneBlock.GetAdditionalTxSerializationSize());
            }
        }
        catch (std::exception &e)
        {
            connman.PushMessage(pfrom, CNetMsgMaker(PROTOCOL_VERSION).Make(NetMsgType::BLOCK, *pblock));
            LogPrintf("GRAPHENE", "Sent regular block instead - encountered error when creating graphene block for peer %d: %s\n",
                      pfrom->id, e.what());
        }
    }
    else
    {
        Misbehaving(pfrom->GetId(), 100);

        return;
    }

//    pfrom->blocksSent += 1;
}
void ClearGrapheneBlockInFlight(CNode *pfrom, uint256 hash)
{
    LOCK(pfrom->cs_mapgrapheneblocksinflight);
    pfrom->mapGrapheneBlocksInFlight.erase(hash);
}

// Adding ReconstructBlockFromGraphene here, check later where it belongs.
//static bool ReconstructBlock(CNode *pfrom, const bool fXVal, int &missingCount, int &unnecessaryCount)
//{
//    AssertLockHeld(cs_xval);
//
//    // We must have all the full tx hashes by this point.  We first check for any repeating
//    // sequences in transaction id's.  This is a possible attack vector and has been used in the past.
//    {
//        std::set<uint256> setHashes(pfrom->grapheneBlockHashes.begin(), pfrom->grapheneBlockHashes.end());
//        if (setHashes.size() != pfrom->grapheneBlockHashes.size())
//        {
//            graphenedata.ClearGrapheneBlockData(pfrom, pfrom->grapheneBlock.GetBlockHeader().GetHash());
//
//            Misbehaving(pfrom->GetId(), 10);
//            return error("Repeating Transaction Id sequence, peer=%d", pfrom->id);
//        }
//    }
//
//    // The total maximum bytes that we can use to create a graphene block. We use shared pointers for
//    // the transactions in the graphene block so we don't need to make as much memory available as we did in
//    // the past. We caluculate the max memory allowed by using the largest block size possible, which is the
//    // (maxMessageSizeMultiplier * excessiveBlockSize), then divide that by the smallest transaction possible
//    // which is 158 bytes on a 32bit system.  That gives us the largest number of transactions possible in a block.
//    // Then we multiply number of possible transactions by the size of a shared pointer.
//    // NOTE * The 158 byte smallest txn possible was found by getting the smallest serialized size of a txn directly
//    //        from the blockchain, on a 32bit system.
//    CTransactionRef dummyptx = nullptr;
//    uint32_t nTxSize = sizeof(dummyptx);
//    // TODO : Darren and Nakul to figure out the maxAllowedSize
//    /** for testing, using bitcoin cash maxMessageMultiplier */
//    uint64_t maxAllowedSize = nTxSize * 16 * 2000000 / 158;
////    uint64_t maxAllowedSize = nTxSize * maxMessageSizeMultiplier * excessiveBlockSize / 158;
//
//    std::map<uint256, CTransactionRef> mapAdditionalTxs;
//    {
//        LOCK(pfrom->cs_grapheneadditionaltxs);
//
//        for (auto tx : pfrom->grapheneAdditionalTxs)
//            mapAdditionalTxs[tx->GetHash()] = tx;
//    }
//
//    // Look for each transaction in our various pools and buffers.
//    // With grapheneBlocks the vTxHashes contains only the first 8 bytes of the tx hash.
//    for (const uint256 &hash : pfrom->grapheneBlockHashes)
//    {
//        // Replace the truncated hash with the full hash value if it exists
//        CTransactionRef ptx = nullptr;
//        if (!hash.IsNull())
//        {
//            bool inMemPool = false;
//            ptx = mempool.get(hash);
//            if (ptx)
//                inMemPool = true;
//
//            bool inMissingTx = pfrom->mapMissingTx.count(hash.GetCheapHash()) > 0;
//            bool inAdditionalTxs = mapAdditionalTxs.count(hash) > 0;
//            bool inOrphanCache = mapOrphanTransactions.count(hash) > 0;
//
//            if ((inMemPool && inMissingTx) || (inOrphanCache && inMissingTx) || (inAdditionalTxs && inMissingTx))
//                unnecessaryCount++;
//
//            if (inAdditionalTxs)
//                ptx = mapAdditionalTxs[hash];
//            else if (inOrphanCache)
//            {
//                ptx = mapOrphanTransactions[hash].tx;
//                setUnVerifiedOrphanTxHash.insert(hash);
//            }
//            else if (inMemPool && fXVal)
//                setPreVerifiedTxHash.insert(hash);
//            else if (inMissingTx)
//                ptx = pfrom->mapMissingTx[hash.GetCheapHash()];
//        }
//        if (!ptx)
//            missingCount++;
//
//        // In order to prevent a memory exhaustion attack we track transaction bytes used to create Block
//        // to see if we've exceeded any limits and if so clear out data and return.
//        // TODO: ClearLargest
//        if (graphenedata.AddGrapheneBlockBytes(nTxSize, pfrom) > maxAllowedSize)
//        {
//            LEAVE_CRITICAL_SECTION(cs_xval); // maintain locking order with vNodes
//            // TODO: Nakul ClearLargest
////            if (ClearLargestGrapheneBlockAndDisconnect(pfrom))
////            {
////                ENTER_CRITICAL_SECTION(cs_xval);
////                return error(
////                        "Reconstructed block %s (size:%llu) has caused max memory limit %llu bytes to be exceeded, peer=%d",
////                        pfrom->grapheneBlock.GetHash().ToString(), pfrom->nLocalGrapheneBlockBytes, maxAllowedSize,
////                        pfrom->id);
////            }
////            ENTER_CRITICAL_SECTION(cs_xval);
//        }
//        if (pfrom->nLocalGrapheneBlockBytes > maxAllowedSize)
//        {
//            graphenedata.ClearGrapheneBlockData(pfrom, pfrom->grapheneBlock.GetBlockHeader().GetHash());
//            pfrom->fDisconnect = true;
//            return error(
//                    "Reconstructed block %s (size:%llu) has caused max memory limit %llu bytes to be exceeded, peer=%d",
//                    pfrom->grapheneBlock.GetHash().ToString(), pfrom->nLocalGrapheneBlockBytes, maxAllowedSize,
//                    pfrom->id);
//        }
//
//        // Add this transaction. If the tx is null we still add it as a placeholder to keep the correct ordering.
//        pfrom->grapheneBlock.vtx.emplace_back(ptx);
//    }
//
//    return true;
//}

bool IsGrapheneBlockValid(CNode *pfrom, const CBlockHeader &header)
{
    // check block header
    CValidationState state;
    if (!CheckBlockHeader(header, state, Params().GetConsensus() ,true))
    {
        return error("Received invalid header for graphene block %s from peer %s", header.GetHash().ToString(),
            pfrom->GetLogName());
    }
    if (state.Invalid())
    {
        return error("Received invalid header for graphene block %s from peer %s", header.GetHash().ToString(),
            pfrom->GetLogName());
    }

    return true;
}

