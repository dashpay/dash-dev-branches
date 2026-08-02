// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <crypto/siphash.h>
#include <protocol.h>
#include <test/fuzz/fuzz.h>
#include <txrequest.h>

#include <bitset>
#include <cstdint>
#include <queue>
#include <vector>

namespace {

constexpr int MAX_TXHASHES = 16;
constexpr int MAX_PEERS = 16;

//! Randomly generated invs used in this test (length is 2 * MAX_TXHASHES; MSG_TX and MSG_DSTX
//! announcements sharing each hash, to exercise same-hash-different-type independence).
constexpr int MAX_INVS = 2 * MAX_TXHASHES;
CInv INVS[MAX_INVS];

//! Precomputed random durations (positive and negative, each ~exponentially distributed).
std::chrono::microseconds DELAYS[256];

struct Initializer
{
    Initializer()
    {
        for (uint8_t txhash = 0; txhash < MAX_TXHASHES; txhash += 1) {
            uint256 hash;
            CSHA256().Write(&txhash, 1).Finalize(hash.begin());
            INVS[2 * txhash] = CInv{MSG_TX, hash};
            INVS[2 * txhash + 1] = CInv{MSG_DSTX, hash};
        }
        int i = 0;
        // DELAYS[N] for N=0..15 is just N microseconds.
        for (; i < 16; ++i) {
            DELAYS[i] = std::chrono::microseconds{i};
        }
        // DELAYS[N] for N=16..127 has randomly-looking but roughly exponentially increasing values up to
        // 198.416453 seconds.
        for (; i < 128; ++i) {
            int diff_bits = ((i - 10) * 2) / 9;
            uint64_t diff = 1 + (CSipHasher(0, 0).Write(i).Finalize() >> (64 - diff_bits));
            DELAYS[i] = DELAYS[i - 1] + std::chrono::microseconds{diff};
        }
        // DELAYS[N] for N=128..255 are negative delays with the same magnitude as N=0..127.
        for (; i < 256; ++i) {
            DELAYS[i] = -DELAYS[255 - i];
        }
    }
} g_initializer;

/** Tester class for TxRequestTracker
 *
 * It includes a naive reimplementation of its behavior, for a limited set
 * of MAX_INVS distinct invs, and MAX_PEERS peer identifiers.
 *
 * All of the public member functions perform the same operation on
 * an actual TxRequestTracker and on the state of the reimplementation.
 * The output of GetRequestable is compared with the expected value
 * as well.
 *
 * Check() calls the TxRequestTracker's sanity check, plus compares the
 * output of the constant accessors (Size(), CountLoad(), CountTracked())
 * with expected values.
 */
class Tester
{
    //! TxRequestTracker object being tested.
    TxRequestTracker m_tracker;

    //! States for inv/peer combinations in the naive data structure.
    enum class State {
        NOTHING, //!< Absence of this inv/peer combination

        // Note that this implementation does not distinguish between DELAYED/READY/BEST variants of CANDIDATE.
        CANDIDATE,
        REQUESTED,
        COMPLETED,
    };

    //! Sequence numbers, incremented whenever a new CANDIDATE is added.
    uint64_t m_current_sequence{0};

    //! List of future 'events' (all inserted reqtimes/exptimes). This is used to implement AdvanceToEvent.
    std::priority_queue<std::chrono::microseconds, std::vector<std::chrono::microseconds>,
        std::greater<std::chrono::microseconds>> m_events;

    //! Information about an inv/peer combination.
    struct Announcement
    {
        std::chrono::microseconds m_time;
        uint64_t m_sequence;
        State m_state{State::NOTHING};
        bool m_preferred;
        uint64_t m_priority; //!< Precomputed priority.
    };

    //! Information about all inv/peer combinations.
    Announcement m_announcements[MAX_INVS][MAX_PEERS];

    //! The current time; can move forward and backward.
    std::chrono::microseconds m_now{244466666};

    //! Delete invs whose only announcements are COMPLETED.
    void Cleanup(int inv)
    {
        bool all_nothing = true;
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            const Announcement& ann = m_announcements[inv][peer];
            if (ann.m_state != State::NOTHING) {
                if (ann.m_state != State::COMPLETED) return;
                all_nothing = false;
            }
        }
        if (all_nothing) return;
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            m_announcements[inv][peer].m_state = State::NOTHING;
        }
    }

    //! Find the current best peer to request from for an inv (or -1 if none).
    int GetSelected(int inv) const
    {
        int ret = -1;
        uint64_t ret_priority = 0;
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            const Announcement& ann = m_announcements[inv][peer];
            // Return -1 if there already is a (non-expired) in-flight request.
            if (ann.m_state == State::REQUESTED) return -1;
            // If it's a viable candidate, see if it has lower priority than the best one so far.
            if (ann.m_state == State::CANDIDATE && ann.m_time <= m_now) {
                if (ret == -1 || ann.m_priority > ret_priority) {
                    std::tie(ret, ret_priority) = std::tie(peer, ann.m_priority);
                }
            }
        }
        return ret;
    }

public:
    Tester() : m_tracker(true) {}

    std::chrono::microseconds Now() const { return m_now; }

    void AdvanceTime(std::chrono::microseconds offset)
    {
        m_now += offset;
        while (!m_events.empty() && m_events.top() <= m_now) m_events.pop();
    }

    void AdvanceToEvent()
    {
        while (!m_events.empty() && m_events.top() <= m_now) m_events.pop();
        if (!m_events.empty()) {
            m_now = m_events.top();
            m_events.pop();
        }
    }

    void DisconnectedPeer(int peer)
    {
        // Apply to naive structure: all announcements for that peer are wiped.
        for (int inv = 0; inv < MAX_INVS; ++inv) {
            if (m_announcements[inv][peer].m_state != State::NOTHING) {
                m_announcements[inv][peer].m_state = State::NOTHING;
                Cleanup(inv);
            }
        }

        // Call TxRequestTracker's implementation.
        m_tracker.DisconnectedPeer(peer);
    }

    void ForgetTxHash(int inv)
    {
        // Apply to naive structure: all announcements for that inv are wiped.
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            m_announcements[inv][peer].m_state = State::NOTHING;
        }
        Cleanup(inv);

        // Call TxRequestTracker's implementation.
        m_tracker.ForgetTxHash(INVS[inv]);
    }

    void ReceivedInv(int peer, int inv, bool preferred, std::chrono::microseconds reqtime)
    {
        // Apply to naive structure: if no announcement for invnum/peer combination
        // already, create a new CANDIDATE; otherwise do nothing.
        Announcement& ann = m_announcements[inv][peer];
        if (ann.m_state == State::NOTHING) {
            ann.m_preferred = preferred;
            ann.m_state = State::CANDIDATE;
            ann.m_time = reqtime;
            ann.m_sequence = m_current_sequence++;
            ann.m_priority = m_tracker.ComputePriority(INVS[inv], peer, ann.m_preferred);

            // Add event so that AdvanceToEvent can quickly jump to the point where its reqtime passes.
            if (reqtime > m_now) m_events.push(reqtime);
        }

        // Call TxRequestTracker's implementation.
        m_tracker.ReceivedInv(peer, INVS[inv], preferred, reqtime);
    }

    void RequestedTx(int peer, int inv, std::chrono::microseconds exptime)
    {
        // Apply to naive structure: if a CANDIDATE announcement exists for peer/inv,
        // convert it to REQUESTED, and change any existing REQUESTED announcement for the same inv to COMPLETED.
        if (m_announcements[inv][peer].m_state == State::CANDIDATE) {
            for (int peer2 = 0; peer2 < MAX_PEERS; ++peer2) {
                if (m_announcements[inv][peer2].m_state == State::REQUESTED) {
                    m_announcements[inv][peer2].m_state = State::COMPLETED;
                }
            }
            m_announcements[inv][peer].m_state = State::REQUESTED;
            m_announcements[inv][peer].m_time = exptime;
        }

        // Add event so that AdvanceToEvent can quickly jump to the point where its exptime passes.
        if (exptime > m_now) m_events.push(exptime);

        // Call TxRequestTracker's implementation.
        m_tracker.RequestedTx(peer, INVS[inv], exptime);
    }

    void ReceivedResponse(int peer, int inv)
    {
        // Apply to naive structure: convert CANDIDATE/REQUESTED to COMPLETED. The response completes an
        // announcement precisely if one existed that wasn't already COMPLETED.
        const State old_state = m_announcements[inv][peer].m_state;
        const bool expected_completed = old_state == State::CANDIDATE || old_state == State::REQUESTED;
        if (old_state != State::NOTHING) {
            m_announcements[inv][peer].m_state = State::COMPLETED;
            Cleanup(inv);
        }

        // Call TxRequestTracker's implementation, and compare its return value with the naive expectation.
        const bool completed = m_tracker.ReceivedResponse(peer, INVS[inv]);
        assert(completed == expected_completed);
    }

    void ReceivedRequestedResponse(int peer, int inv)
    {
        // Apply to naive structure: unlike ReceivedResponse, only a REQUESTED announcement is
        // completed. Anything else -- including a CANDIDATE, which exists from the moment an inv is
        // processed -- is left exactly as it was.
        const bool expected_completed = m_announcements[inv][peer].m_state == State::REQUESTED;
        if (expected_completed) {
            m_announcements[inv][peer].m_state = State::COMPLETED;
            Cleanup(inv);
        }

        // Call TxRequestTracker's implementation, and compare its return value with the naive expectation.
        const bool completed = m_tracker.ReceivedRequestedResponse(peer, INVS[inv]);
        assert(completed == expected_completed);
    }

    void GetRequestable(int peer)
    {
        // Implement using naive structure:

        //! list of (sequence number, inv) pairs.
        std::vector<std::pair<uint64_t, int>> result;
        std::vector<std::pair<NodeId, CInv>> expected_expired;
        for (int inv = 0; inv < MAX_INVS; ++inv) {
            // Mark any expired REQUESTED announcements as COMPLETED.
            for (int peer2 = 0; peer2 < MAX_PEERS; ++peer2) {
                Announcement& ann2 = m_announcements[inv][peer2];
                if (ann2.m_state == State::REQUESTED && ann2.m_time <= m_now) {
                    expected_expired.emplace_back(peer2, INVS[inv]);
                    ann2.m_state = State::COMPLETED;
                    break;
                }
            }
            // And delete invs with only COMPLETED announcements left.
            Cleanup(inv);
            // CANDIDATEs for which this announcement has the highest priority get returned.
            const Announcement& ann = m_announcements[inv][peer];
            if (ann.m_state == State::CANDIDATE && GetSelected(inv) == peer) {
                result.emplace_back(ann.m_sequence, inv);
            }
        }
        // Sort the results by sequence number.
        std::sort(result.begin(), result.end());
        std::sort(expected_expired.begin(), expected_expired.end());

        // Compare with TxRequestTracker's implementation.
        std::vector<std::pair<NodeId, CInv>> expired;
        const auto actual = m_tracker.GetRequestable(peer, m_now, &expired);
        std::sort(expired.begin(), expired.end());
        assert(expired == expected_expired);

        m_tracker.PostGetRequestableSanityCheck(m_now);
        assert(result.size() == actual.size());
        for (size_t pos = 0; pos < actual.size(); ++pos) {
            assert(INVS[result[pos].second] == actual[pos]);
        }
    }

    void Check()
    {
        // Compare CountTracked and CountLoad with naive structure.
        size_t total = 0;
        for (int peer = 0; peer < MAX_PEERS; ++peer) {
            size_t tracked = 0;
            size_t inflight = 0;
            size_t candidates = 0;
            for (int inv = 0; inv < MAX_INVS; ++inv) {
                tracked += m_announcements[inv][peer].m_state != State::NOTHING;
                inflight += m_announcements[inv][peer].m_state == State::REQUESTED;
                candidates += m_announcements[inv][peer].m_state == State::CANDIDATE;
            }
            assert(m_tracker.Count(peer) == tracked);
            assert(m_tracker.CountInFlight(peer) == inflight);
            assert(m_tracker.CountCandidates(peer) == candidates);
            total += tracked;
        }
        // Compare Size.
        assert(m_tracker.Size() == total);

        // Invoke internal consistency check of TxRequestTracker object.
        m_tracker.SanityCheck();
    }
};
} // namespace

FUZZ_TARGET(txrequest)
{
    // Tester object (which encapsulates a TxRequestTracker).
    Tester tester;

    // Decode the input as a sequence of instructions with parameters
    auto it = buffer.begin();
    while (it != buffer.end()) {
        int cmd = *(it++) % 12;
        int peer, invnum, delaynum;
        switch (cmd) {
        case 0: // Make time jump to the next event (m_time of CANDIDATE or REQUESTED)
            tester.AdvanceToEvent();
            break;
        case 1: // Change time
            delaynum = it == buffer.end() ? 0 : *(it++);
            tester.AdvanceTime(DELAYS[delaynum]);
            break;
        case 2: // Query for requestable txs
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            tester.GetRequestable(peer);
            break;
        case 3: // Peer went offline
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            tester.DisconnectedPeer(peer);
            break;
        case 4: // No longer need tx
            invnum = it == buffer.end() ? 0 : *(it++);
            tester.ForgetTxHash(invnum % MAX_INVS);
            break;
        case 5: // Received immediate preferred inv
        case 6: // Same, but non-preferred.
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            invnum = it == buffer.end() ? 0 : *(it++);
            tester.ReceivedInv(peer, invnum % MAX_INVS, cmd & 1,
                std::chrono::microseconds::min());
            break;
        case 7: // Received delayed preferred inv
        case 8: // Same, but non-preferred.
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            invnum = it == buffer.end() ? 0 : *(it++);
            delaynum = it == buffer.end() ? 0 : *(it++);
            tester.ReceivedInv(peer, invnum % MAX_INVS, cmd & 1,
                tester.Now() + DELAYS[delaynum]);
            break;
        case 9: // Requested tx from peer
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            invnum = it == buffer.end() ? 0 : *(it++);
            delaynum = it == buffer.end() ? 0 : *(it++);
            tester.RequestedTx(peer, invnum % MAX_INVS, tester.Now() + DELAYS[delaynum]);
            break;
        case 10: // Received response
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            invnum = it == buffer.end() ? 0 : *(it++);
            tester.ReceivedResponse(peer, invnum % MAX_INVS);
            break;
        case 11: // Received response to a GETDATA we actually sent
            peer = it == buffer.end() ? 0 : *(it++) % MAX_PEERS;
            invnum = it == buffer.end() ? 0 : *(it++);
            tester.ReceivedRequestedResponse(peer, invnum % MAX_INVS);
            break;
        default:
            assert(false);
        }
    }
    tester.Check();
}
