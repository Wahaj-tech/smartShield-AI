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
)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Create the executable
add_executable(packet_analyzer ${SOURCES})

# DPI Live capture executable
add_executable(dpi_live src/main_live.cpp ${DPI_COMMON_SOURCES})
target_link_libraries(dpi_live PRIVATE pcap pthread)

# DPI file-based executable
add_executable(dpi_engine_bin src/main_dpi.cpp ${DPI_COMMON_SOURCES})
target_link_libraries(dpi_engine_bin PRIVATE pcap pthread)
