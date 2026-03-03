#include "dpi_engine.h"
#include "live_capture.h"
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

    // ---- Demo blocking rules (uncomment to test) ----
    // engine.blockDomain("youtube.com");
    // engine.blockDomain("*.youtube.com");
    // engine.blockDomain("*.googlevideo.com");
    // engine.blockApp(DPI::AppType::YOUTUBE);

    PacketAnalyzer::LiveCapture capture;

    // Run capture in a separate thread so we can handle signals
    std::thread capture_thread([&]() {
        capture.start("wlo1", &engine);
    });

    // Wait for signal
    while (g_running.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // Graceful shutdown
    std::cout << "[main] Stopping capture...\n";
    capture.stop();

    if (capture_thread.joinable())
        capture_thread.join();

    engine.stop();

    // Print final report
    std::cout << engine.generateReport();
    std::cout << engine.generateClassificationReport();

    return 0;
}