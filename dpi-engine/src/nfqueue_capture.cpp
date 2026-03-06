#include "nfqueue_capture.h"
#include "dpi_engine.h"
#include "rule_manager.h"

#include <iostream>
#include <cstring>
#include <cerrno>
#include <chrono>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>

extern "C" {
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
}

namespace DPI {

// ============================================================================
// Synthetic Ethernet header (14 bytes) prepended to raw IP packets so that
// the existing DPI pipeline (which expects Ethernet-framed data) works
// unchanged.  EtherType = 0x0800 (IPv4).
// ============================================================================
static const uint8_t FAKE_ETH_HEADER[14] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // dst MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // src MAC
    0x08, 0x00                             // EtherType = IPv4
};

// ============================================================================
// Construction / Destruction
// ============================================================================

NFQueueCapture::NFQueueCapture() = default;

NFQueueCapture::~NFQueueCapture() {
    stop();
}

// ============================================================================
// start()
// ============================================================================

bool NFQueueCapture::start(uint16_t queue_num, DPIEngine* engine) {
    if (running_.load()) return false;
    if (!engine) return false;

    engine_       = engine;
    rule_manager_ = &engine->getRuleManager();

    // --- 1. Open NFQUEUE handle ---
    nfq_h_ = nfq_open();
    if (!nfq_h_) {
        std::cerr << "[NFQUEUE] nfq_open() failed\n";
        return false;
    }

    // Unbind any existing AF_INET handler (may fail — not critical)
    nfq_unbind_pf(nfq_h_, AF_INET);

    if (nfq_bind_pf(nfq_h_, AF_INET) < 0) {
        std::cerr << "[NFQUEUE] nfq_bind_pf() failed\n";
        nfq_close(nfq_h_);
        nfq_h_ = nullptr;
        return false;
    }

    // --- 2. Create the queue ---
    nfq_qh_ = nfq_create_queue(nfq_h_, queue_num, &NFQueueCapture::packetCallback, this);
    if (!nfq_qh_) {
        std::cerr << "[NFQUEUE] nfq_create_queue(" << queue_num << ") failed\n";
        nfq_close(nfq_h_);
        nfq_h_ = nullptr;
        return false;
    }

    // --- 3. Set copy-packet mode (full packet) ---
    if (nfq_set_mode(nfq_qh_, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "[NFQUEUE] nfq_set_mode() failed\n";
        nfq_destroy_queue(nfq_qh_);
        nfq_close(nfq_h_);
        nfq_h_ = nullptr;
        nfq_qh_ = nullptr;
        return false;
    }

    // Optional: increase kernel queue length to reduce drops under load
    nfq_set_queue_maxlen(nfq_qh_, 8192);

    nfq_fd_ = nfq_fd(nfq_h_);

    running_.store(true);
    capture_thread_ = std::thread(&NFQueueCapture::recvLoop, this);

    std::cout << "[NFQUEUE] Listening on queue " << queue_num << std::endl;
    return true;
}

// ============================================================================
// stop()
// ============================================================================

void NFQueueCapture::stop() {
    if (!running_.load())
        return;

    running_.store(false);

    // Destroy queue so recv() stops delivering packets
    if (nfq_qh_) {
        nfq_destroy_queue(nfq_qh_);
        nfq_qh_ = nullptr;
    }

    // Wait for capture thread to exit
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }

    // Close NFQUEUE handle
    if (nfq_h_) {
        nfq_close(nfq_h_);
        nfq_h_ = nullptr;
    }

    std::cout << "[NFQUEUE] Capture stopped (accepted="
              << pkts_accepted_.load()
              << ", dropped=" << pkts_dropped_.load()
              << ")\n";
}

// ============================================================================
// recvLoop() — runs in capture_thread_
// ============================================================================

void NFQueueCapture::recvLoop() {
    // Buffer large enough for jumbo frames + netlink overhead
    alignas(16) char buf[65536 + 256];

    struct pollfd pfd;
    pfd.fd     = nfq_fd_;
    pfd.events = POLLIN;

    while (running_.load(std::memory_order_acquire)) {
        // Use poll() with a 200ms timeout so we can check `running_`
        // periodically and exit cleanly on CTRL+C.
        int poll_ret = ::poll(&pfd, 1, 200);

        if (poll_ret < 0) {
            if (errno == EINTR) continue;
            if (!running_.load(std::memory_order_acquire)) break;
            std::cerr << "[NFQUEUE] poll() error: " << std::strerror(errno) << "\n";
            break;
        }

        if (poll_ret == 0) continue;  // timeout, check running_ again

        if (!(pfd.revents & POLLIN)) continue;

        int rv = ::recv(nfq_fd_, buf, sizeof(buf), MSG_DONTWAIT);
        if (rv < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (!running_.load(std::memory_order_acquire)) break;
            std::cerr << "[NFQUEUE] recv() error: " << std::strerror(errno) << "\n";
            break;
        }
        if (rv == 0) break;

        // Dispatch to packetCallback
        nfq_handle_packet(nfq_h_, buf, rv);
    }
}

// ============================================================================
// packetCallback() — static, called by libnetfilter_queue per packet
// ============================================================================

int NFQueueCapture::packetCallback(struct nfq_q_handle* qh,
                                    struct nfgenmsg* /*nfmsg*/,
                                    struct nfq_data* nfa,
                                    void* data) {
    auto* self = static_cast<NFQueueCapture*>(data);

    // --- Extract NFQUEUE packet id (for verdict) ---
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return -1;
    uint32_t nfq_id = ntohl(ph->packet_id);

    // --- Extract raw IP payload ---
    unsigned char* payload = nullptr;
    int len = nfq_get_payload(nfa, &payload);
    if (len < 0 || !payload) {
        nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
        return 0;
    }

    // --- Fast path: check blocked-flows cache ---
    uint32_t src_ip, dst_ip;
    uint8_t  protocol;
    uint16_t src_port, dst_port;

    if (parseQuick(payload, len, src_ip, dst_ip, protocol, src_port, dst_port)) {
        FiveTuple ft{src_ip, dst_ip, src_port, dst_port, protocol};
        if (self->isFlowBlocked(ft)) {
            // Already classified and blocked — NF_DROP immediately
            nfq_set_verdict(qh, nfq_id, NF_DROP, 0, nullptr);
            self->pkts_dropped_.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }
    }

    // --- Deferred verdict: inject into DPI pipeline, wait for result ---
    if (self->engine_ && len > 0) {
        // Assign a DPI-engine packet-id for this packet
        uint32_t pkt_id = self->next_packet_id_.fetch_add(1,
                              std::memory_order_relaxed);

        // Create a pending verdict (promise/future pair)
        auto pv     = std::make_shared<PendingVerdict>();
        auto future = pv->promise.get_future();

        {
            std::lock_guard<std::mutex> lock(self->pending_mutex_);
            self->pending_verdicts_[pkt_id] = pv;
        }

        // Prepend synthetic Ethernet header and inject into DPI
        size_t framed_len = 14 + static_cast<size_t>(len);
        if (framed_len <= 65550) {
            uint8_t framed[65550];
            std::memcpy(framed, FAKE_ETH_HEADER, 14);
            std::memcpy(framed + 14, payload, static_cast<size_t>(len));
            self->engine_->injectLivePacket(framed, framed_len, pkt_id);
        }

        // Wait for FastPath classification to complete
        PacketAction action = PacketAction::FORWARD;   // fail-open default
        auto status = future.wait_for(std::chrono::milliseconds(500));

        if (status == std::future_status::ready) {
            action = future.get();
        } else {
            // Timeout — clean up and accept
            std::lock_guard<std::mutex> lock(self->pending_mutex_);
            self->pending_verdicts_.erase(pkt_id);
        }

        // Issue NFQUEUE verdict
        if (action == PacketAction::DROP) {
            nfq_set_verdict(qh, nfq_id, NF_DROP, 0, nullptr);
            self->pkts_dropped_.fetch_add(1, std::memory_order_relaxed);
            std::cout << "[NFQUEUE] Packet DROPPED" << std::endl;
        } else {
            nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
            self->pkts_accepted_.fetch_add(1, std::memory_order_relaxed);
        }
    } else {
        // No engine — just accept
        nfq_set_verdict(qh, nfq_id, NF_ACCEPT, 0, nullptr);
        self->pkts_accepted_.fetch_add(1, std::memory_order_relaxed);
    }

    return 0;
}

// ============================================================================
// resolveVerdict() — called from DPIEngine::handleOutput (any FP thread)
// ============================================================================

void NFQueueCapture::resolveVerdict(uint32_t packet_id,
                                     const FiveTuple& tuple,
                                     PacketAction action) {
    std::shared_ptr<PendingVerdict> pv;

    {
        std::lock_guard<std::mutex> lock(pending_mutex_);
        auto it = pending_verdicts_.find(packet_id);
        if (it == pending_verdicts_.end()) return;   // already timed-out
        pv = it->second;
        pending_verdicts_.erase(it);
    }

    // Cache blocked flows so subsequent packets skip the DPI pipeline
    if (action == PacketAction::DROP) {
        markFlowBlocked(tuple);
    }

    pv->promise.set_value(action);
}

// ============================================================================
// parseQuick() — minimal zero-copy IPv4+TCP/UDP header parse
// ============================================================================

bool NFQueueCapture::parseQuick(const uint8_t* ip_data, int ip_len,
                                 uint32_t& src_ip, uint32_t& dst_ip,
                                 uint8_t& protocol,
                                 uint16_t& src_port, uint16_t& dst_port) {
    if (ip_len < 20) return false;

    // IPv4 check
    uint8_t version = (ip_data[0] >> 4) & 0x0F;
    if (version != 4) return false;

    uint8_t ihl = ip_data[0] & 0x0F;
    int ip_hdr_len = ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > ip_len) return false;

    protocol = ip_data[9];
    std::memcpy(&src_ip, ip_data + 12, 4);  // network byte order
    std::memcpy(&dst_ip, ip_data + 16, 4);

    // Convert to host byte order — matches RuleManager::parseIP layout.
    // parseIP("1.2.3.4") → 0x04030201 (little-endian on x86).
    // ntohl(big-endian 0x01020304) → 0x04030201.  ✓
    src_ip = ntohl(src_ip);
    dst_ip = ntohl(dst_ip);

    const uint8_t* transport = ip_data + ip_hdr_len;
    int transport_len = ip_len - ip_hdr_len;

    if (protocol == 6) {
        // TCP — need at least 4 bytes for ports
        if (transport_len < 4) return false;
        src_port = ntohs(*reinterpret_cast<const uint16_t*>(transport));
        dst_port = ntohs(*reinterpret_cast<const uint16_t*>(transport + 2));
        return true;
    }

    if (protocol == 17) {
        // UDP — 8-byte header
        if (transport_len < 8) return false;
        src_port = ntohs(*reinterpret_cast<const uint16_t*>(transport));
        dst_port = ntohs(*reinterpret_cast<const uint16_t*>(transport + 2));
        return true;
    }

    // Other protocols — no ports
    src_port = 0;
    dst_port = 0;
    return true;
}

// ============================================================================
// Blocked-flows cache helpers
// ============================================================================

void NFQueueCapture::markFlowBlocked(const FiveTuple& tuple) {
    std::unique_lock lock(flows_mutex_);
    blocked_flows_.insert(tuple);
    blocked_flows_.insert(tuple.reverse());
}

bool NFQueueCapture::isFlowBlocked(const FiveTuple& tuple) const {
    std::shared_lock lock(flows_mutex_);
    return blocked_flows_.count(tuple) > 0;
}

} // namespace DPI
