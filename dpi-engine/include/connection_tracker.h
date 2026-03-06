#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include "flow_csv_writer.h"
#include <unordered_map>
#include <shared_mutex>
#include <vector>
#include <chrono>
#include <functional>

namespace DPI {

// ============================================================================
// Connection Tracker - Maintains flow table for all active connections
// ============================================================================
//
// Each FP thread has its own ConnectionTracker instance (no sharing needed
// since connections are consistently hashed to the same FP).
//
// Features:
// - Track connection state (NEW -> ESTABLISHED -> CLASSIFIED -> CLOSED)
// - Store classification results (app type, SNI)
// - Maintain per-flow statistics
// - Timeout inactive connections
// ============================================================================

// Callback invoked when a flow finishes (timeout / close / eviction).
// Receives the Connection that is about to be removed.
using FlowFinishedCallback = std::function<void(const Connection&)>;

class ConnectionTracker {
public:
    ConnectionTracker(int fp_id, size_t max_connections = 100000);
    
    // Get or create connection entry
    // Returns pointer to existing or newly created connection
    Connection* getOrCreateConnection(const FiveTuple& tuple);
    
    // Get existing connection (returns nullptr if not found)
    Connection* getConnection(const FiveTuple& tuple);
    
    // Update connection with new packet
    void updateConnection(Connection* conn, size_t packet_size, bool is_outbound);
    
    // Mark connection as classified
    void classifyConnection(Connection* conn, AppType app, const std::string& sni);
    
    // Mark connection as blocked
    void blockConnection(Connection* conn);
    
    // Mark connection as closed
    void closeConnection(const FiveTuple& tuple);
    
    // Remove timed-out connections
    // Returns number of connections removed
    size_t cleanupStale(std::chrono::seconds timeout = std::chrono::seconds(300));
    
    // Get all connections (for reporting)
    std::vector<Connection> getAllConnections() const;
    
    // Get active connection count
    size_t getActiveCount() const;
    
    // Get statistics
    struct TrackerStats {
        size_t active_connections;
        size_t total_connections_seen;
        size_t classified_connections;
        size_t blocked_connections;
    };
    
    TrackerStats getStats() const;
    
    // Clear all connections
    void clear();
    
    // Iteration callback for all connections
    void forEach(std::function<void(const Connection&)> callback) const;

    // Register a callback that fires when a flow is finished/removed.
    // Used for ML dataset logging.
    void setFlowFinishedCallback(FlowFinishedCallback cb);

private:
    int fp_id_;
    size_t max_connections_;
    
    // Connection table
    // Note: FiveTuple hash ensures consistent mapping, so we don't need
    // to handle bidirectional flows specially here
    std::unordered_map<FiveTuple, Connection, FiveTupleHash> connections_;
    
    // Statistics
    size_t total_seen_ = 0;
    size_t classified_count_ = 0;
    size_t blocked_count_ = 0;
    
    // Callback fired when a flow is removed
    FlowFinishedCallback flow_finished_cb_;

    // For LRU eviction if table gets full
    void evictOldest();

    // Notify flow finished (calls callback if set)
    void notifyFlowFinished(const Connection& conn);
};

// ============================================================================
// Global Connection Table - Aggregates stats from all FP trackers
// ============================================================================
class GlobalConnectionTable {
public:
    GlobalConnectionTable(size_t num_fps);
    
    // Register an FP's tracker
    void registerTracker(int fp_id, ConnectionTracker* tracker);
    
    // Get aggregated statistics
    struct GlobalStats {
        size_t total_active_connections;
        size_t total_connections_seen;
        std::unordered_map<AppType, size_t> app_distribution;
        std::vector<std::pair<std::string, size_t>> top_domains;
    };
    
    GlobalStats getGlobalStats() const;
    
    // Generate report
    std::string generateReport() const;

private:
    std::vector<ConnectionTracker*> trackers_;
    mutable std::shared_mutex mutex_;
};

} // namespace DPI

#endif // CONNECTION_TRACKER_H
