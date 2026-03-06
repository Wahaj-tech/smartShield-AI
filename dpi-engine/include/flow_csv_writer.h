#ifndef FLOW_CSV_WRITER_H
#define FLOW_CSV_WRITER_H

#include <string>
#include <fstream>
#include <mutex>
#include <cstdint>

namespace DPI {

// ============================================================================
// FlowCSVWriter - Thread-safe CSV writer for ML dataset generation
// ============================================================================
//
// Singleton that writes one row per completed network flow to flow_dataset.csv.
// All FP threads share this single writer; a mutex serialises file I/O.
//
// The file is opened in append mode so rows are continuously added across
// runs.  The CSV header is written only when the file is first created (or
// is empty).
//
// Performance: the only work done under the lock is a single fprintf-style
// write, which is fast enough that it will not measurably slow down the
// DPI pipeline.
// ============================================================================

struct FlowRecord {
    std::string domain;           // From DNS extractor / SNI
    std::string protocol;         // "TCP", "UDP", "HTTPS"
    uint64_t    packet_count;     // Total packets in flow
    double      avg_packet_size;  // Average packet size in bytes
    double      flow_duration;    // Duration in seconds
    double      packets_per_second; // packet_count / flow_duration
    double      bytes_per_second;   // (packet_count * avg_packet_size) / flow_duration
    std::string sni;              // TLS Server Name (may be empty)
    std::string category;         // ML category label (streaming, social_media, etc.)
};

class FlowCSVWriter {
public:
    // Get the single global instance
    static FlowCSVWriter& instance();

    // Open (or reopen) the CSV file.  Called once at engine start-up.
    // `path` is the full path to the CSV file.
    bool open(const std::string& path);

    // Append one flow record.  Thread-safe.
    void writeRecord(const FlowRecord& record);

    // Flush & close the file (called at engine shutdown).
    void close();

    // Non-copyable / non-movable
    FlowCSVWriter(const FlowCSVWriter&)            = delete;
    FlowCSVWriter& operator=(const FlowCSVWriter&) = delete;

private:
    FlowCSVWriter() = default;
    ~FlowCSVWriter();

    // Escape a field for CSV (wrap in quotes if it contains comma/quote)
    static std::string csvEscape(const std::string& field);

    // Map a domain to a traffic category for ML labeling
    static std::string domainToCategory(const std::string& domain);

    std::ofstream file_;
    std::mutex    mutex_;
    bool          is_open_ = false;
};

} // namespace DPI

#endif // FLOW_CSV_WRITER_H
