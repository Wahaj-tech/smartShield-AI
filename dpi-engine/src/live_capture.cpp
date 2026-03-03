#include "live_capture.h"
#include "dpi_engine.h"
#include <iostream>
#include <cstring>

namespace PacketAnalyzer {

LiveCapture::LiveCapture()
    : handle_(nullptr), running_(false), loop_exited_(true) {}

LiveCapture::~LiveCapture() {
    stop();
}

bool LiveCapture::start(const std::string& interface, DPI::DPIEngine* engine) {
    if (!engine) {
        std::cerr << "[LiveCapture] Error: null DPIEngine pointer" << std::endl;
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    std::memset(errbuf, 0, sizeof(errbuf));

    // ---------------------------------------------------------------
    // Use pcap_create + pcap_activate instead of pcap_open_live.
    // This lets us enable IMMEDIATE MODE, which is critical on Linux:
    // modern libpcap uses TPACKET_V3 with block-based ring buffers.
    // Without immediate mode, low-rate traffic stays buffered in the
    // kernel indefinitely and pcap_dispatch never delivers it.
    // ---------------------------------------------------------------
    handle_ = pcap_create(interface.c_str(), errbuf);
    if (!handle_) {
        std::cerr << "[LiveCapture] pcap_create failed: " << errbuf << std::endl;
        return false;
    }

    // Snapshot length — capture full packets
    if (pcap_set_snaplen(handle_, 65535) != 0) {
        std::cerr << "[LiveCapture] pcap_set_snaplen failed" << std::endl;
        pcap_close(handle_); handle_ = nullptr;
        return false;
    }

    // Promiscuous mode — see all traffic on the wire
    if (pcap_set_promisc(handle_, 1) != 0) {
        std::cerr << "[LiveCapture] pcap_set_promisc failed" << std::endl;
        pcap_close(handle_); handle_ = nullptr;
        return false;
    }

    // Read timeout — 100 ms (shorter for responsiveness)
    if (pcap_set_timeout(handle_, 100) != 0) {
        std::cerr << "[LiveCapture] pcap_set_timeout failed" << std::endl;
        pcap_close(handle_); handle_ = nullptr;
        return false;
    }

    // *** KEY FIX: Enable immediate mode ***
    // Forces the kernel to deliver packets as soon as they arrive
    // instead of waiting for a full TPACKET_V3 block.
    if (pcap_set_immediate_mode(handle_, 1) != 0) {
        std::cerr << "[LiveCapture] pcap_set_immediate_mode failed" << std::endl;
        pcap_close(handle_); handle_ = nullptr;
        return false;
    }

    // Activate the handle — this is where the fd is actually opened
    int activate_status = pcap_activate(handle_);
    if (activate_status < 0) {
        // Negative = error
        std::cerr << "[LiveCapture] pcap_activate failed: "
                  << pcap_statustostr(activate_status);
        if (activate_status == PCAP_ERROR) {
            std::cerr << " — " << pcap_geterr(handle_);
        }
        std::cerr << std::endl;
        pcap_close(handle_); handle_ = nullptr;
        return false;
    }
    if (activate_status > 0) {
        // Positive = warning (e.g. promisc not supported), continue anyway
        std::cerr << "[LiveCapture] pcap_activate warning: "
                  << pcap_statustostr(activate_status) << std::endl;
    }

    // Log datalink type for debugging
    int dlt = pcap_datalink(handle_);
    std::cout << "Datalink type: " << dlt << std::endl;
    std::cout << "Datalink name: " << pcap_datalink_val_to_name(dlt) << std::endl;
    if (dlt != DLT_EN10MB) {
        std::cerr << "Warning: Non-Ethernet datalink detected. Parser offset may be incorrect." << std::endl;
    }

    std::cout << "[LiveCapture] Live capture started on: " << interface << std::endl;
    running_.store(true, std::memory_order_release);
    loop_exited_.store(false, std::memory_order_release);

    // -----------------------------------------------------------------
    // Use pcap_dispatch in a loop instead of pcap_loop.
    // pcap_dispatch processes one batch of packets then returns, letting
    // us check the running_ flag between batches.
    //
    // cnt = -1 → process ALL packets available in one buffer read,
    // which is more efficient than a fixed count.
    // -----------------------------------------------------------------
    while (running_.load(std::memory_order_acquire)) {
        int ret = pcap_dispatch(handle_, -1, packetHandler,
                                reinterpret_cast<u_char*>(engine));
        if (ret == PCAP_ERROR) {
            std::cerr << "[LiveCapture] pcap_dispatch error: "
                      << pcap_geterr(handle_) << std::endl;
            break;
        }
        if (ret == PCAP_ERROR_BREAK) {
            // pcap_breakloop was called
            std::cout << "[LiveCapture] Capture loop broken via pcap_breakloop"
                      << std::endl;
            break;
        }
        // ret == 0 → timeout with no packets, just loop back
    }

    running_.store(false, std::memory_order_release);
    loop_exited_.store(true, std::memory_order_release);

    // Safe to close here — we are out of pcap_dispatch
    {
        std::lock_guard<std::mutex> lock(handle_mutex_);
        if (handle_) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
    }

    std::cout << "[LiveCapture] Capture loop exited" << std::endl;
    return true;
}

void LiveCapture::stop() {
    // Signal the loop to exit
    running_.store(false, std::memory_order_release);

    // Tell pcap_dispatch to return immediately
    {
        std::lock_guard<std::mutex> lock(handle_mutex_);
        if (handle_) {
            pcap_breakloop(handle_);
        }
    }

    // Do NOT pcap_close here.
    // The handle is closed by start() after its loop exits.
    // If stop() is called from a different thread, start()'s loop will
    // see running_==false or get PCAP_ERROR_BREAK, exit, and close.
    // If stop() is called after start() already returned (e.g. from the
    // destructor), handle_ is already nullptr — the lock_guard check
    // above handles that safely.
}

void LiveCapture::packetHandler(u_char* userData,
                                const struct pcap_pkthdr* header,
                                const u_char* packet) {
    if (!userData || !header || !packet) return;

    // Guard against malformed pcap header
    if (header->caplen == 0 || header->caplen > 65535) return;

    DPI::DPIEngine* engine = reinterpret_cast<DPI::DPIEngine*>(userData);
    engine->injectLivePacket(packet, header->caplen);
}

}