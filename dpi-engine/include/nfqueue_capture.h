#ifndef NFQUEUE_CAPTURE_H
#define NFQUEUE_CAPTURE_H

#include "types.h"
#include <atomic>
#include <thread>
#include <shared_mutex>
#include <mutex>
#include <unordered_set>
#include <unordered_map>
#include <memory>
#include <future>
#include <cstdint>

// Forward-declare NFQUEUE C types so callers don't need the headers
struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

namespace DPI {

class DPIEngine;
class RuleManager;

// ============================================================================
// NFQueueCapture — Intercept packets via Linux NFQUEUE
// ============================================================================
//
// Architecture (classify-then-verdict):
//
//   NFQUEUE callback
//     ├─ flow-cache hit → NF_DROP immediately (fast path)
//     └─ inject into DPI pipeline, wait for verdict
//          └─ FastPath classifies + logs + checks rules
//               └─ handleOutput → resolveVerdict(packet_id, action)
//                    └─ callback resumes, issues NF_ACCEPT or NF_DROP
//
// Every packet goes through full classification before a verdict is issued,
// so Application Detection logs appear even for blocked packets.
//
// Required iptables rule (example — all outbound):
//   sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
//
// ============================================================================

class NFQueueCapture {
public:
    NFQueueCapture();
    ~NFQueueCapture();

    /// Open the queue and start the receive loop (spawns a thread).
    bool start(uint16_t queue_num, DPIEngine* engine);

    /// Shut down the capture loop and close the queue.
    void stop();

    /// Mark a five-tuple (and its reverse) as blocked so that future
    /// packets on the same flow receive NF_DROP.
    void markFlowBlocked(const FiveTuple& tuple);

    /// Check whether a flow is already in the blocked cache.
    bool isFlowBlocked(const FiveTuple& tuple) const;

    /// Called by DPIEngine::handleOutput (from any FP thread) when a
    /// packet has been fully classified.  Resolves the pending verdict
    /// so the NFQUEUE callback can issue NF_ACCEPT / NF_DROP.
    void resolveVerdict(uint32_t packet_id, const FiveTuple& tuple,
                        PacketAction action);

private:
    // ---- NFQUEUE callback (C linkage required by libnetfilter_queue) ----
    static int packetCallback(struct nfq_q_handle* qh,
                              struct nfgenmsg* nfmsg,
                              struct nfq_data* nfa,
                              void* data);

    // ---- Internal helpers ----
    void recvLoop();

    /// Parse an IP packet just enough to extract five-tuple.
    static bool parseQuick(const uint8_t* ip_data, int ip_len,
                           uint32_t& src_ip, uint32_t& dst_ip,
                           uint8_t& protocol,
                           uint16_t& src_port, uint16_t& dst_port);

    // ---- Data members ----

    DPIEngine*   engine_       = nullptr;
    RuleManager* rule_manager_ = nullptr;

    struct nfq_handle*   nfq_h_  = nullptr;
    struct nfq_q_handle* nfq_qh_ = nullptr;
    int                  nfq_fd_ = -1;

    std::atomic<bool> running_{false};
    std::thread       capture_thread_;

    // Blocked-flows cache (populated when FastPath blocks a flow)
    mutable std::shared_mutex flows_mutex_;
    std::unordered_set<FiveTuple, FiveTupleHash> blocked_flows_;

    // Pending verdicts — one per in-flight packet awaiting classification
    struct PendingVerdict {
        std::promise<PacketAction> promise;
    };
    std::mutex pending_mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<PendingVerdict>> pending_verdicts_;

    // Monotonic packet-id generator (shared with DPIEngine via parameter)
    std::atomic<uint32_t> next_packet_id_{0};

    // Stats (atomic, lock-free)
    std::atomic<uint64_t> pkts_accepted_{0};
    std::atomic<uint64_t> pkts_dropped_{0};
    std::atomic<uint64_t> enobufs_count_{0};
};

} // namespace DPI

#endif // NFQUEUE_CAPTURE_H
