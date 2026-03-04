#include "control_interface.h"
#include "dpi_engine.h"
#include "rule_manager.h"
#include "types.h"

#include <nlohmann/json.hpp>

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <algorithm>
#include <cctype>

using json = nlohmann::json;

namespace DPI {

// ============================================================================
// Construction / Destruction
// ============================================================================

ControlInterface::ControlInterface(DPIEngine& engine, uint16_t port)
    : engine_(engine), port_(port), server_fd_(-1), running_(false) {}

ControlInterface::~ControlInterface() {
    stop();
}

// ============================================================================
// Start / Stop
// ============================================================================

void ControlInterface::start() {
    if (running_.load()) return;

    running_.store(true);
    server_thread_ = std::thread(&ControlInterface::serverLoop, this);
    std::cout << "[ControlInterface] Started on 127.0.0.1:" << port_ << std::endl;
}

void ControlInterface::stop() {
    if (!running_.load()) return;

    running_.store(false);

    // Close the listening socket so accept() unblocks
    if (server_fd_ >= 0) {
        ::shutdown(server_fd_, SHUT_RDWR);
        ::close(server_fd_);
        server_fd_ = -1;
    }

    if (server_thread_.joinable()) {
        server_thread_.join();
    }

    std::cout << "[ControlInterface] Stopped" << std::endl;
}

// ============================================================================
// Server Loop (runs in its own thread)
// ============================================================================

void ControlInterface::serverLoop() {
    // 1. Create TCP socket
    server_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        std::cerr << "[ControlInterface] socket() failed: "
                  << std::strerror(errno) << std::endl;
        return;
    }

    // Allow fast restart
    int opt = 1;
    ::setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 2. Bind to localhost
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port_);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (::bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[ControlInterface] bind() failed: "
                  << std::strerror(errno) << std::endl;
        ::close(server_fd_);
        server_fd_ = -1;
        return;
    }

    // 3. Listen (backlog = 4 is plenty for a control channel)
    if (::listen(server_fd_, 4) < 0) {
        std::cerr << "[ControlInterface] listen() failed: "
                  << std::strerror(errno) << std::endl;
        ::close(server_fd_);
        server_fd_ = -1;
        return;
    }

    // 4. Accept loop
    while (running_.load()) {
        sockaddr_in client_addr{};
        socklen_t   client_len = sizeof(client_addr);

        int client_fd = ::accept(server_fd_,
                                 reinterpret_cast<sockaddr*>(&client_addr),
                                 &client_len);
        if (client_fd < 0) {
            // accept() was interrupted because we closed the socket during stop()
            if (!running_.load()) break;
            std::cerr << "[ControlInterface] accept() failed: "
                      << std::strerror(errno) << std::endl;
            continue;
        }

        // Handle the client synchronously (control commands are tiny & rare)
        handleClient(client_fd);
    }
}

// ============================================================================
// Handle a single client connection
// ============================================================================

void ControlInterface::handleClient(int client_fd) {
    char buffer[4096];
    std::string message;

    // Read until the client closes its write-half or we fill the buffer.
    // Control messages are small JSON objects, so a single read usually suffices.
    while (true) {
        ssize_t n = ::read(client_fd, buffer, sizeof(buffer) - 1);
        if (n <= 0) break;
        buffer[n] = '\0';
        message.append(buffer, static_cast<size_t>(n));

        // If we already received a complete JSON object, stop reading.
        // Simple heuristic: the message contains at least one '{' and '}'.
        if (message.find('}') != std::string::npos) break;
    }

    if (!message.empty()) {
        std::string response = processCommand(message);
        ::write(client_fd, response.c_str(), response.size());
    }

    ::close(client_fd);
}

// ============================================================================
// Process a JSON command
// ============================================================================

std::string ControlInterface::processCommand(const std::string& message) {
    try {
        auto j = json::parse(message);
        std::string action = j.value("action", "");

        RuleManager& rm = engine_.getRuleManager();

        // ----- block commands -----
        if (action == "block_domain") {
            std::string domain = j.at("domain").get<std::string>();
            rm.blockDomain(domain);
            return R"({"status":"ok"})";
        }

        if (action == "block_ip") {
            std::string ip = j.at("ip").get<std::string>();
            rm.blockIP(ip);
            return R"({"status":"ok"})";
        }

        if (action == "block_app") {
            std::string app_name = j.at("app").get<std::string>();
            // Convert string → AppType via the engine helper
            engine_.blockApp(app_name);
            return R"({"status":"ok"})";
        }

        if (action == "block_port") {
            uint16_t port = j.at("port").get<uint16_t>();
            rm.blockPort(port);
            return R"({"status":"ok"})";
        }

        // ----- unblock commands -----
        if (action == "unblock_domain") {
            std::string domain = j.at("domain").get<std::string>();
            rm.unblockDomain(domain);
            return R"({"status":"ok"})";
        }

        if (action == "unblock_ip") {
            std::string ip = j.at("ip").get<std::string>();
            rm.unblockIP(ip);
            return R"({"status":"ok"})";
        }

        if (action == "unblock_app") {
            std::string app_name = j.at("app").get<std::string>();
            engine_.unblockApp(app_name);
            return R"({"status":"ok"})";
        }

        if (action == "unblock_port") {
            uint16_t port = j.at("port").get<uint16_t>();
            rm.unblockPort(port);
            return R"({"status":"ok"})";
        }

        // ----- query commands -----
        if (action == "get_stats") {
            auto stats = rm.getStats();
            json resp;
            resp["status"] = "ok";
            resp["stats"]["blocked_ips"]     = stats.blocked_ips;
            resp["stats"]["blocked_apps"]    = stats.blocked_apps;
            resp["stats"]["blocked_domains"] = stats.blocked_domains;
            resp["stats"]["blocked_ports"]   = stats.blocked_ports;

            // Include the actual lists for convenience
            resp["stats"]["ip_list"]     = rm.getBlockedIPs();
            resp["stats"]["domain_list"] = rm.getBlockedDomains();

            std::vector<std::string> app_names;
            for (auto a : rm.getBlockedApps()) {
                app_names.push_back(appTypeToString(a));
            }
            resp["stats"]["app_list"] = app_names;

            return resp.dump();
        }

        // Unknown action
        json err;
        err["status"]  = "error";
        err["message"] = "unknown action: " + action;
        return err.dump();

    } catch (const json::exception& e) {
        json err;
        err["status"]  = "error";
        err["message"] = std::string("JSON parse error: ") + e.what();
        return err.dump();
    } catch (const std::exception& e) {
        json err;
        err["status"]  = "error";
        err["message"] = std::string("error: ") + e.what();
        return err.dump();
    }
}

} // namespace DPI
