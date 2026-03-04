#include "dpi_engine.h"
#include "nfqueue_capture.h"
#include "control_interface.h"
#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

static std::atomic<bool> g_running{true};

static void signalHandler(int /*sig*/) {
    std::cout << "\n[main] Caught signal, shutting down...\n";
    g_running.store(false, std::memory_order_release);
}

int main() {
    // Install signal handlers for clean Ctrl-C shutdown
    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);

    DPI::DPIEngine::Config config;
    config.num_load_balancers = 2;
    config.fps_per_lb = 2;

    DPI::DPIEngine engine(config);

    if (!engine.initialize())
        return 1;

    engine.start();

    // Start the control interface (TCP JSON on 127.0.0.1:9091)
    DPI::ControlInterface control(engine);
    control.start();

    // ---- NFQUEUE-based active packet interception ----
    // Requires:  sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
    DPI::NFQueueCapture capture;

    // Wire up the verdict callback so that when FastPath finishes
    // classifying a packet, NFQueueCapture can resolve the pending
    // NFQUEUE verdict (NF_ACCEPT or NF_DROP).
    engine.setVerdictCallback(
        [&capture](uint32_t packet_id, const DPI::FiveTuple& tuple,
                   DPI::PacketAction action) {
            capture.resolveVerdict(packet_id, tuple, action);
        });

    if (!capture.start(0, &engine)) {
        std::cerr << "[main] Failed to start NFQUEUE capture.  "
                     "Make sure you run as root and have the iptables rule:\n"
                     "  sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0\n";
        control.stop();
        engine.stop();
        return 1;
    }

    // Wait for signal
while (g_running.load(std::memory_order_acquire)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

// Graceful shutdown
std::cout << "[main] Stopping capture...\n";

// Stop NFQUEUE capture
capture.stop();

// Stop control interface
control.stop();

// Stop DPI engine
engine.stop();

std::cout << "\n\n====================================\n";
std::cout << "       SmartShield Session Report\n";
std::cout << "====================================\n";

// Print packet statistics
std::cout << engine.generateReport() << std::endl;

// Print application classification report
std::cout << engine.generateClassificationReport() << std::endl;

std::cout << "====================================\n";
std::cout << "SmartShield shutdown complete\n";

return 0;

    
}