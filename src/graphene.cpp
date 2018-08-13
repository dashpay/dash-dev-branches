// Copyright (c) 2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "graphene.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "net.h"
#include "netmessagemaker.h"
#include "policy/policy.h"
#include "pow.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"

// static bool ReconstructBlock(CNode *pfrom, const bool fXVal, int &missingCount, int &unnecessaryCount);

//
// Global variables
//

CGrapheneBlockData graphenedata;

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

CGrapheneBlockTx::CGrapheneBlockTx(uint256 blockHash, std::vector<CTransactionRef> vTx)
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

void CGrapheneBlockData::IncrementDecodeFailures()
{
    LOCK(cs_graphenestats);
    nDecodeFailures += 1;
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

void CGrapheneBlockData::UpdateResponseTime(double nResponseTime)
{
    LOCK(cs_graphenestats);

    // only update stats if IBD is complete
    if (IsGrapheneBlockEnabled())
        updateStats(mapGrapheneBlockResponseTime, nResponseTime);
}

void CGrapheneBlockData::UpdateValidationTime(double nValidationTime)
{
    LOCK(cs_graphenestats);

    // only update stats if IBD is complete
    if (IsGrapheneBlockEnabled())
        updateStats(mapGrapheneBlockValidationTime, nValidationTime);
}

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
bool CGrapheneBlockData::CheckGrapheneBlockTimer(const uint256 &hash)
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
    return true;
}

// The timer is cleared as soon as we request a block or graphene block.
void CGrapheneBlockData::ClearGrapheneBlockTimer(const uint256 &hash)
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

void CGrapheneBlockData::ClearGrapheneBlockData(CNode *pnode, const uint256 &hash)
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

bool IsGrapheneBlockEnabled()
{
    return fGrapheneBlockEnabled;
}

bool CanGrapheneBlockBeDownloaded(CNode *pto)
{
    if (pto->GrapheneCapable() && !GetBoolArg("-connect-graphene-force", false))
        return true;
    else if (pto->GrapheneCapable() && GetBoolArg("-connect-graphene-force", false))
    {
        // If connect-graphene-force is true then we have to check that this node is in fact a connect-graphene node.

        // When -connect-graphene-force is true we will only download graphene blocks from a peer or peers that
        // are using -connect-graphene=<ip>.  This is an undocumented setting used for setting up performance testing
        // of graphene blocks, such as, going over the GFC and needing to have graphene blocks always come from the same
        // peer or group of peers.  Also, this is a one way street.  Graphene blocks will flow ONLY from the remote peer
        // to the peer that has invoked -connect-graphene.

        // Check if this node is also a connect-graphene node
        if (mapMultiArgs.count("-connect-graphene") > 0)
        {
            BOOST_FOREACH(const std::string &strAddrNode , mapMultiArgs.at("-connect-graphene") )
            {
                if (pto->GetAddrName() == strAddrNode) return true;
            }
        }
    }

    return false;
}

void ClearGrapheneBlockInFlight(CNode *pfrom, const uint256 &hash)
{
    LOCK(pfrom->cs_mapgrapheneblocksinflight);
    pfrom->mapGrapheneBlocksInFlight.erase(hash);
}

void AddGrapheneBlockInFlight(CNode *pfrom, const uint256 &hash)
{
    LOCK(pfrom->cs_mapgrapheneblocksinflight);
    pfrom->mapGrapheneBlocksInFlight.insert(
        std::pair<uint256, CNode::CGrapheneBlockInFlight>(hash, CNode::CGrapheneBlockInFlight()));
}

bool IsGrapheneBlockValid(CNode *pfrom, const CBlockHeader &header)
{
    // check block header
    CValidationState state;
    if (!CheckBlockHeader(header, state, Params().GetConsensus(), true))
    {
        return error("Received invalid header for graphene block %s from peer %d", header.GetHash().ToString(),
            pfrom->id);
    }
    if (state.Invalid())
    {
        return error("Received invalid header for graphene block %s from peer %s", header.GetHash().ToString(),
            pfrom->GetLogName());
    }

    return true;
}

CMemPoolInfo GetGrapheneMempoolInfo() { return CMemPoolInfo(mempool.size()); }

void RequestFailoverBlock(CNode *pfrom, uint256 blockHash, CConnman& connman)
{
    LogPrint("Graphene", "Requesting full block as failover from peer %d\n", pfrom->id);
    std::vector<CInv> vGetData;
    vGetData.push_back(CInv(MSG_BLOCK, blockHash));
    connman.PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::GETDATA, vGetData));
}
