#pragma once

#include <pcap.h>
#include <string>
#include <atomic>
#include <mutex>

// Forward declaration (cleaner, avoids circular include)
namespace DPI {
class DPIEngine;
}

namespace PacketAnalyzer {

class LiveCapture {
public:
    LiveCapture();
    ~LiveCapture();

    // Blocking call — runs capture loop until stop() is called.
    bool start(const std::string& interface, DPI::DPIEngine* engine);

    // Thread-safe. Signals the capture loop to exit.
    void stop();

private:
    static void packetHandler(u_char* userData,
                              const struct pcap_pkthdr* header,
                              const u_char* packet);

    pcap_t* handle_;
    std::mutex handle_mutex_;
    std::atomic<bool> running_;
    std::atomic<bool> loop_exited_;  // set when start() loop finishes
};

}