#include "fast_path.h"
#include "flow_csv_writer.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// FastPathProcessor Implementation
// ============================================================================

FastPathProcessor::FastPathProcessor(int fp_id,
                                     RuleManager* rule_manager,
                                     PacketOutputCallback output_callback)
    : fp_id_(fp_id),
      input_queue_(10000),
      conn_tracker_(fp_id),
      rule_manager_(rule_manager),
      output_callback_(std::move(output_callback)) {

    // Register flow-finished callback for ML dataset logging.
    // Each FP thread has its own ConnectionTracker, and the callback is
    // invoked from that FP's thread only, so the only contention is on
    // FlowCSVWriter's internal mutex (minimal, since flow completions
    // are infrequent relative to per-packet processing).
    conn_tracker_.setFlowFinishedCallback([this](const Connection& conn) {
        uint64_t total_packets = conn.packets_in + conn.packets_out;
        uint64_t total_bytes   = conn.bytes_in   + conn.bytes_out;

        double avg_pkt_size = total_packets > 0
            ? static_cast<double>(total_bytes) / total_packets
            : 0.0;

        double duration_sec = std::chrono::duration<double>(
            conn.last_seen - conn.first_seen).count();

        // Determine protocol string
        std::string protocol;
        if (conn.app_type == AppType::HTTPS || conn.app_type == AppType::TLS ||
            conn.tuple.dst_port == 443 || conn.tuple.src_port == 443) {
            protocol = "HTTPS";
        } else if (conn.tuple.protocol == 6) {
            protocol = "TCP";
        } else if (conn.tuple.protocol == 17) {
            protocol = "UDP";
        } else {
            protocol = "unknown";
        }

        // Determine domain — prefer explicit domain, fall back to SNI
        std::string domain_str;
        if (!conn.domain.empty()) {
            domain_str = conn.domain;
        } else if (!conn.sni.empty()) {
            domain_str = conn.sni;
        } else {
            domain_str = "unknown";
        }

        // Normalize the domain to strip subdomains/CDN prefixes
        std::string norm_domain = normalizeDomain(domain_str);

        // Compute ML features
        double packets_per_sec = (duration_sec > 0.0)
            ? static_cast<double>(total_packets) / duration_sec
            : 0.0;
        double bytes_per_sec = (duration_sec > 0.0)
            ? (static_cast<double>(total_packets) * avg_pkt_size) / duration_sec
            : 0.0;

        // If the connection still has a generic protocol type (HTTPS/HTTP)
        // but we have a domain, re-run sniToAppType on the normalized
        // domain as a last-resort reclassification.
        AppType final_type = conn.app_type;
        if ((final_type == AppType::HTTPS || final_type == AppType::HTTP ||
             final_type == AppType::TLS   || final_type == AppType::UNKNOWN) &&
            norm_domain != "unknown") {
            AppType reclassified = sniToAppType(norm_domain);
            if (reclassified != AppType::HTTPS && reclassified != AppType::UNKNOWN) {
                final_type = reclassified;
            }
        }

        // Derive category from the (potentially upgraded) AppType
        std::string category = appTypeToCategory(final_type);

        FlowRecord record;
        record.domain            = norm_domain;
        record.protocol          = protocol;
        record.packet_count      = total_packets;
        record.avg_packet_size   = avg_pkt_size;
        record.flow_duration     = duration_sec;
        record.packets_per_second = packets_per_sec;
        record.bytes_per_second  = bytes_per_sec;
        record.sni               = conn.sni.empty() ? "unknown" : conn.sni;
        record.category          = category;

        FlowCSVWriter::instance().writeRecord(record);
    });
}

FastPathProcessor::~FastPathProcessor() {
    stop();
}

void FastPathProcessor::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&FastPathProcessor::run, this);
    
    std::cout << "[FP" << fp_id_ << "] Started\n";
}

void FastPathProcessor::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    std::cout << "[FP" << fp_id_ << "] Stopped (processed " 
              << packets_processed_ << " packets)\n";
}

void FastPathProcessor::run() {
    while (running_) {
        // Get packet from input queue
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (!job_opt) {
            // Periodically cleanup stale connections
            conn_tracker_.cleanupStale(std::chrono::seconds(300));
            continue;
        }
        
        packets_processed_++;
        
        // Process the packet
        PacketAction action = processPacket(*job_opt);
        
        // Call output callback
        if (output_callback_) {
            output_callback_(*job_opt, action);
        }
        
        // Update stats
        if (action == PacketAction::DROP) {
            packets_dropped_++;
        } else {
            packets_forwarded_++;
        }
    }
}

PacketAction FastPathProcessor::processPacket(PacketJob& job) {
    // Get or create connection
    Connection* conn = conn_tracker_.getOrCreateConnection(job.tuple);
    if (!conn) {
        // Should not happen, but handle gracefully
        return PacketAction::FORWARD;
    }

    // --- DNS-to-flow correlation ---
    // If this is a new connection with no domain yet, look up the
    // destination IP in the DNS cache to correlate it with the earlier
    // DNS query/response.
    if (conn->domain.empty()) {
        std::string cached_domain = dns_cache_.lookup(job.tuple.dst_ip);
        if (!cached_domain.empty()) {
            conn->domain = cached_domain;
            if (conn->sni.empty()) {
                conn->sni = cached_domain;
            }
        }
    }
    
    // Update connection stats
    bool is_outbound = true;  // In this model, all packets from user are outbound
    conn_tracker_.updateConnection(conn, job.data.size(), is_outbound);
    
    // Update TCP state if applicable
    if (job.tuple.protocol == 6) {  // TCP
        updateTCPState(conn, job.tcp_flags);
    }
    
    // If connection is already blocked, drop immediately
    if (conn->state == ConnectionState::BLOCKED) {
        return PacketAction::DROP;
    }
    
    // If connection not yet classified, or classified but still missing
    // SNI/domain info (e.g. port-based fallback), or only classified as
    // DNS — try to inspect payload.  TLS SNI / HTTP Host overrides DNS.
    if ((conn->state != ConnectionState::CLASSIFIED ||
         conn->app_type == AppType::DNS ||
         conn->sni.empty()) &&
        job.payload_length > 0) {
        if (inspectPayload(job, conn)) {
            // DNS query for a blocked domain — propagate classification
            // and log the detection before returning DROP
            job.domain = conn->sni;
            job.app    = conn->app_type;

            if (!conn->sni.empty()) {
                std::string norm = normalizeDomain(job.domain);
                std::cout << "[FP" << fp_id_ << "] App: " << appTypeToString(job.app)
                          << " | Domain: " << norm << std::endl;
                std::cout << "[SmartShield] Rule matched: " << norm << std::endl;
            }
            return PacketAction::DROP;
        }
    }
    
    // Propagate connection's classification to the job
    job.domain = conn->sni;
    job.app = conn->app_type;

    // Track per-app stats (single FP thread, no lock needed)
    if (job.app != AppType::UNKNOWN) {
        app_packet_counts_[job.app]++;
        app_byte_counts_[job.app] += job.data.size();
    }

    // Throttled console print: once per new classification
    // Uses normalized domain for cleaner output
    if (!conn->sni.empty() && conn->packets_in + conn->packets_out <= 2) {
        std::string norm = normalizeDomain(job.domain);
        std::cout << "[FP" << fp_id_ << "] App: " << appTypeToString(job.app)
                  << " | Domain: " << norm << std::endl;
    }
    
    // Check rules (even for classified connections, as rules might change)
    return checkRules(job, conn);
}

bool FastPathProcessor::inspectPayload(PacketJob& job, Connection* conn) {
    if (job.tuple.protocol == 17 && 
    (job.tuple.dst_port == 443 || job.tuple.src_port == 443)) {

    std::cout << "QUIC traffic detected (UDP 443)\n";
}
    if (job.payload_length == 0 || job.payload_offset >= job.data.size()) {
        return false;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    
    // Try TLS SNI extraction first (most common for HTTPS)
    if (tryExtractSNI(job, conn)) {
        return false;
    }
    
    // Try HTTP Host header extraction
    if (tryExtractHTTPHost(job, conn)) {
        return false;
    }
    
    // Check for DNS (port 53)
    if (job.tuple.dst_port == 53 || job.tuple.src_port == 53) {
        // --- Parse DNS responses to populate DNS→IP cache ---
        auto dns_resp = DNSExtractor::extractResponse(payload, job.payload_length);
        if (dns_resp && !dns_resp->domain.empty()) {
            for (uint32_t ip : dns_resp->ips) {
                dns_cache_.insert(ip, dns_resp->domain);
            }
        }

        auto domain = DNSExtractor::extractQuery(payload, job.payload_length);
        if (domain) {
            // ── DNS-level blocking (Pi-hole style) ──
            // Check if the queried domain is blocked BEFORE forwarding
            // the DNS query.  Dropping the query means the browser never
            // receives an IP address → the website cannot load.
            if (rule_manager_ && rule_manager_->isDomainBlocked(*domain)) {
                std::cout << "[DNS] BLOCKED query: " << *domain << std::endl;
                conn_tracker_.classifyConnection(conn, AppType::DNS, *domain);
                conn->domain = *domain;
                conn_tracker_.blockConnection(conn);
                return true;  // signal DROP
            }

            conn_tracker_.classifyConnection(conn, AppType::DNS, *domain);
            // Directly propagate DNS domain into connection
            conn->domain = *domain;
            if (conn->sni.empty()) {
                conn->sni = *domain;
            }
            return false;
        }
    }
    
    // Basic port-based classification as fallback
    if (job.tuple.dst_port == 80) {
        conn_tracker_.classifyConnection(conn, AppType::HTTP, "");
    } else if (job.tuple.dst_port == 443) {
        conn_tracker_.classifyConnection(conn, AppType::HTTPS, "");
    }
    return false;
}

bool FastPathProcessor::tryExtractSNI(const PacketJob& job, Connection* conn) {
    // Only for port 443 (HTTPS) or if it looks like TLS
    if (job.tuple.dst_port != 443 && job.payload_length < 50) {
        return false;
    }
    
    if (job.payload_offset >= job.data.size() || job.payload_length == 0) {
        return false;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    auto sni = SNIExtractor::extract(payload, job.payload_length);
    if (sni) {
        sni_extractions_++;
        
        // Map SNI to app type
        AppType app = sniToAppType(*sni);
        conn_tracker_.classifyConnection(conn, app, *sni);

        // Directly propagate SNI and app_type into connection fields
        // so the dataset writer always has them, even if
        // classifyConnection was already called earlier with empty
        // values or a generic protocol type.
        conn->sni = *sni;
        if (conn->domain.empty()) {
            conn->domain = *sni;
        }
        // Force app_type upgrade: if the SNI-based classification is
        // more specific than the current one, apply it directly.
        if (app != AppType::UNKNOWN && app != AppType::HTTPS &&
            app != AppType::HTTP && app != conn->app_type) {
            conn->app_type = app;
        }
        
        if (app != AppType::UNKNOWN && app != AppType::HTTPS) {
            classification_hits_++;
        }
        
        return true;
    }
    
    return false;
}

bool FastPathProcessor::tryExtractHTTPHost(const PacketJob& job, Connection* conn) {
    // Only for port 80 (HTTP)
    if (job.tuple.dst_port != 80) {
        return false;
    }
    
    if (job.payload_offset >= job.data.size() || job.payload_length == 0) {
        return false;
    }
    
    const uint8_t* payload = job.data.data() + job.payload_offset;
    auto host = HTTPHostExtractor::extract(payload, job.payload_length);
    if (host) {
        AppType app = sniToAppType(*host);
        conn_tracker_.classifyConnection(conn, app, *host);

        // Propagate HTTP Host as domain and SNI equivalent
        conn->sni = *host;
        if (conn->domain.empty()) {
            conn->domain = *host;
        }
        
        if (app != AppType::UNKNOWN && app != AppType::HTTP) {
            classification_hits_++;
        }
        
        return true;
    }
    
    return false;
}

PacketAction FastPathProcessor::checkRules(const PacketJob& job, Connection* conn) {
    if (!rule_manager_) {
        return PacketAction::FORWARD;
    }
    
    // Use job.domain (may be richer than conn->sni for newly classified flows)
    const std::string& domain = !job.domain.empty() ? job.domain : conn->sni;
    
    // Check blocking rules
    auto block_reason = rule_manager_->shouldBlock(
        job.tuple.src_ip,
        job.tuple.dst_port,
        conn->app_type,
        domain
    );
    
    if (block_reason) {
        // Log the block with SmartShield branding
        std::cout << "[SmartShield] Rule matched: " << block_reason->detail << std::endl;

        std::ostringstream ss;
        ss << "[FP" << fp_id_ << "] BLOCKED packet: ";
        
        switch (block_reason->type) {
            case RuleManager::BlockReason::IP:
                ss << "IP " << block_reason->detail;
                break;
            case RuleManager::BlockReason::APP:
                ss << "App " << block_reason->detail;
                break;
            case RuleManager::BlockReason::DOMAIN:
                ss << "Domain " << block_reason->detail;
                break;
            case RuleManager::BlockReason::PORT:
                ss << "Port " << block_reason->detail;
                break;
        }
        
        std::cout << ss.str() << std::endl;
        
        // Mark connection as blocked
        conn_tracker_.blockConnection(conn);
        
        return PacketAction::DROP;
    }
    
    return PacketAction::FORWARD;
}

void FastPathProcessor::updateTCPState(Connection* conn, uint8_t tcp_flags) {
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t RST = 0x04;
    
    if (tcp_flags & SYN) {
        if (tcp_flags & ACK) {
            conn->syn_ack_seen = true;
        } else {
            conn->syn_seen = true;
        }
    }
    
    if (conn->syn_seen && conn->syn_ack_seen && (tcp_flags & ACK)) {
        if (conn->state == ConnectionState::NEW) {
            conn->state = ConnectionState::ESTABLISHED;
        }
    }
    
    if (tcp_flags & FIN) {
        conn->fin_seen = true;
    }
    
    if (tcp_flags & RST) {
        conn->state = ConnectionState::CLOSED;
    }
    
    if (conn->fin_seen && (tcp_flags & ACK)) {
        conn->state = ConnectionState::CLOSED;
    }
}

FastPathProcessor::FPStats FastPathProcessor::getStats() const {
    FPStats stats;
    stats.packets_processed = packets_processed_.load();
    stats.packets_forwarded = packets_forwarded_.load();
    stats.packets_dropped = packets_dropped_.load();
    stats.connections_tracked = conn_tracker_.getActiveCount();
    stats.sni_extractions = sni_extractions_.load();
    stats.classification_hits = classification_hits_.load();
    return stats;
}

// ============================================================================
// FPManager Implementation
// ============================================================================

FPManager::FPManager(int num_fps,
                     RuleManager* rule_manager,
                     PacketOutputCallback output_callback) {
    
    // Create FP processors (each has its own input queue)
    for (int i = 0; i < num_fps; i++) {
        auto fp = std::make_unique<FastPathProcessor>(i, rule_manager, output_callback);
        fps_.push_back(std::move(fp));
    }
    
    std::cout << "[FPManager] Created " << num_fps << " fast path processors\n";
}

FPManager::~FPManager() {
    stopAll();
}

void FPManager::startAll() {
    for (auto& fp : fps_) {
        fp->start();
    }
}

void FPManager::stopAll() {
    // Stop all FPs (they'll shutdown their own queues)
    for (auto& fp : fps_) {
        fp->stop();
    }
}

FPManager::AggregatedStats FPManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0, 0, 0};
    
    for (const auto& fp : fps_) {
        auto fp_stats = fp->getStats();
        stats.total_processed += fp_stats.packets_processed;
        stats.total_forwarded += fp_stats.packets_forwarded;
        stats.total_dropped += fp_stats.packets_dropped;
        stats.total_connections += fp_stats.connections_tracked;
    }
    
    return stats;
}

std::unordered_map<AppType, uint64_t> FPManager::getAppPacketCounts() const {
    std::unordered_map<AppType, uint64_t> merged;
    for (const auto& fp : fps_) {
        for (const auto& [app, count] : fp->getAppPacketCounts()) {
            merged[app] += count;
        }
    }
    return merged;
}

std::unordered_map<AppType, uint64_t> FPManager::getAppByteCounts() const {
    std::unordered_map<AppType, uint64_t> merged;
    for (const auto& fp : fps_) {
        for (const auto& [app, count] : fp->getAppByteCounts()) {
            merged[app] += count;
        }
    }
    return merged;
}

std::string FPManager::generateClassificationReport() const {
    // Aggregate app distribution across all FPs
    std::unordered_map<AppType, size_t> app_counts;
    std::unordered_map<std::string, size_t> domain_counts;
    size_t total_classified = 0;
    size_t total_unknown = 0;
    
    for (const auto& fp : fps_) {
        fp->getConnectionTracker().forEach([&](const Connection& conn) {
            app_counts[conn.app_type]++;
            
            if (conn.app_type == AppType::UNKNOWN) {
                total_unknown++;
            } else {
                total_classified++;
            }
            
            if (!conn.sni.empty()) {
                domain_counts[conn.sni]++;
            }
        });
    }
    
    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║                 APPLICATION CLASSIFICATION REPORT             ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    size_t total = total_classified + total_unknown;
    double classified_pct = total > 0 ? (100.0 * total_classified / total) : 0;
    double unknown_pct = total > 0 ? (100.0 * total_unknown / total) : 0;
    
    ss << "║ Total Connections:    " << std::setw(10) << total << "                           ║\n";
    ss << "║ Classified:           " << std::setw(10) << total_classified 
       << " (" << std::fixed << std::setprecision(1) << classified_pct << "%)                  ║\n";
    ss << "║ Unidentified:         " << std::setw(10) << total_unknown
       << " (" << std::fixed << std::setprecision(1) << unknown_pct << "%)                  ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                    APPLICATION DISTRIBUTION                   ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // Sort apps by count
    std::vector<std::pair<AppType, size_t>> sorted_apps(
        app_counts.begin(), app_counts.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& pair : sorted_apps) {
        double pct = total > 0 ? (100.0 * pair.second / total) : 0;
        
        // Create a simple bar graph
        int bar_len = static_cast<int>(pct / 5);  // 20 chars max
        std::string bar(bar_len, '#');
        
        ss << "║ " << std::setw(15) << std::left << appTypeToString(pair.first)
           << std::setw(8) << std::right << pair.second
           << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
           << std::setw(20) << std::left << bar << "   ║\n";
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

} // namespace DPI
