#ifndef CONTROL_INTERFACE_H
#define CONTROL_INTERFACE_H

#include <string>
#include <thread>
#include <atomic>

namespace DPI {

class DPIEngine;

// ============================================================================
// Control Interface - TCP JSON control plane for the DPI engine
// ============================================================================
//
// Runs a TCP server on 127.0.0.1:9091 in its own thread.
// Accepts JSON commands from an external backend (e.g. FastAPI) to
// add/remove blocking rules at runtime without stopping packet processing.
//
// Supported commands:
//   block_domain   { "action":"block_domain",  "domain":"example.com" }
//   block_ip       { "action":"block_ip",       "ip":"1.2.3.4"        }
//   block_app      { "action":"block_app",      "app":"YOUTUBE"       }
//   block_port     { "action":"block_port",     "port":8080           }
//   unblock_domain { "action":"unblock_domain", "domain":"example.com"}
//   unblock_ip     { "action":"unblock_ip",     "ip":"1.2.3.4"       }
//   unblock_app    { "action":"unblock_app",    "app":"YOUTUBE"       }
//   unblock_port   { "action":"unblock_port",   "port":8080           }
//   get_stats      { "action":"get_stats"                              }
//
// Response:
//   { "status":"ok" }                     on success
//   { "status":"ok", "stats":{...} }      for get_stats
//   { "status":"error", "message":"..." } on failure
// ============================================================================

class ControlInterface {
public:
    explicit ControlInterface(DPIEngine& engine, uint16_t port = 9091);
    ~ControlInterface();

    // Start the control server (spawns server thread)
    void start();

    // Stop the control server (closes socket, joins thread)
    void stop();

private:
    // Main accept-loop running in server_thread_
    void serverLoop();

    // Handle a single connected client (read command, respond, close)
    void handleClient(int client_fd);

    // Process a JSON command string; returns the JSON response string
    std::string processCommand(const std::string& message);

    DPIEngine& engine_;
    uint16_t port_;
    int server_fd_;
    std::atomic<bool> running_;
    std::thread server_thread_;
};

} // namespace DPI

#endif // CONTROL_INTERFACE_H
