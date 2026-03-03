#include "dpi_engine.h"
#include "live_capture.h"

int main() {

    DPI::DPIEngine::Config config;
    DPI::DPIEngine engine(config);

    if (!engine.initialize())
        return 1;

    engine.start();

    PacketAnalyzer::LiveCapture capture;

    capture.start("wlo1", &engine);

    return 0;
}