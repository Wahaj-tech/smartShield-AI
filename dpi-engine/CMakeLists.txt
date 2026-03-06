cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Source files
set(SOURCES
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)

# Common DPI sources
set(DPI_COMMON_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/dpi_engine.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/sni_extractor.cpp
    src/types.cpp
    src/live_capture.cpp
    src/control_interface.cpp
    src/nfqueue_capture.cpp
    src/flow_csv_writer.cpp
)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# nlohmann/json (header-only) — fetched automatically if not already installed
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# Create the executable
add_executable(packet_analyzer ${SOURCES})

# DPI Live capture executable (NFQUEUE-based active firewall)
add_executable(dpi_live src/main_live.cpp ${DPI_COMMON_SOURCES})
target_link_libraries(dpi_live PRIVATE pcap pthread nlohmann_json::nlohmann_json netfilter_queue nfnetlink)

# DPI file-based executable
add_executable(dpi_engine_bin src/main_dpi.cpp ${DPI_COMMON_SOURCES})
target_link_libraries(dpi_engine_bin PRIVATE pcap pthread nlohmann_json::nlohmann_json netfilter_queue nfnetlink)
