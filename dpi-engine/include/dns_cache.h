#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <string>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <cstdint>

namespace DPI {

// ============================================================================
// DNSCache — Maps resolved IP addresses to domain names
// ============================================================================
//
// When DNS responses are parsed, the resolved IPs are stored here.
// When a new TCP/UDP connection is created, the ConnectionTracker looks up
// the destination IP in this cache to correlate it with the DNS domain.
//
// Thread safety: all public methods are mutex-protected.  In practice the
// cache is per-FP so contention is very low (only the owning FP thread
// writes/reads), but the mutex is there for safety.
//
// Entries expire after a configurable TTL (default 5 minutes) to avoid
// stale mappings.
// ============================================================================

class DNSCache {
public:
    DNSCache() = default;

    /// Store an IP→domain mapping (called when a DNS response is parsed).
    void insert(uint32_t ip, const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_[ip] = {domain, std::chrono::steady_clock::now()};
    }

    /// Look up a domain by destination IP.
    /// Returns empty string if not found or expired.
    std::string lookup(uint32_t ip, std::chrono::seconds ttl = std::chrono::seconds(300)) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(ip);
        if (it == entries_.end()) return {};

        auto age = std::chrono::steady_clock::now() - it->second.timestamp;
        if (age > ttl) return {};  // expired

        return it->second.domain;
    }

    /// Remove stale entries older than ttl.
    void cleanup(std::chrono::seconds ttl = std::chrono::seconds(300)) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        for (auto it = entries_.begin(); it != entries_.end(); ) {
            if ((now - it->second.timestamp) > ttl) {
                it = entries_.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

private:
    struct Entry {
        std::string domain;
        std::chrono::steady_clock::time_point timestamp;
    };

    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, Entry> entries_;
};

} // namespace DPI

#endif // DNS_CACHE_H
