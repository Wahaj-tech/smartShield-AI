#include "sni_extractor.h"
#include <cstring>
#include <algorithm>

namespace DPI {

// ============================================================================
// TLS SNI Extractor Implementation
// ============================================================================

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           data[2];
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    // Minimum TLS record: 5 bytes header + 4 bytes handshake header
    if (length < 9) return false;
    
    // Check TLS record header
    // Byte 0: Content Type (should be 0x16 = Handshake)
    if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    
    // Bytes 1-2: TLS Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    // We accept 0x0300 (SSL 3.0) through 0x0304 (TLS 1.3)
    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    
    // Bytes 3-4: Record length
    uint16_t record_length = readUint16BE(payload + 3);
    if (record_length > length - 5) return false;
    
    // Check handshake header (starts at byte 5)
    // Byte 5: Handshake Type (should be 0x01 = Client Hello)
    if (payload[5] != HANDSHAKE_CLIENT_HELLO) return false;
    
    return true;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }
    
    // Skip TLS record header (5 bytes)
    size_t offset = 5;
    
    // Skip handshake header
    // Byte 0: Handshake type (already checked)
    // Bytes 1-3: Length (skip past the 4-byte handshake header)
    offset += 4;
    
    // Client Hello body
    // Bytes 0-1: Client version
    offset += 2;
    
    // Bytes 2-33: Random (32 bytes)
    offset += 32;
    
    // Session ID
    if (offset >= length) return std::nullopt;
    uint8_t session_id_length = payload[offset];
    offset += 1 + session_id_length;
    
    // Cipher suites
    if (offset + 2 > length) return std::nullopt;
    uint16_t cipher_suites_length = readUint16BE(payload + offset);
    offset += 2 + cipher_suites_length;
    
    // Compression methods
    if (offset >= length) return std::nullopt;
    uint8_t compression_methods_length = payload[offset];
    offset += 1 + compression_methods_length;
    
    // Extensions
    if (offset + 2 > length) return std::nullopt;
    uint16_t extensions_length = readUint16BE(payload + offset);
    offset += 2;
    
    size_t extensions_end = offset + extensions_length;
    if (extensions_end > length) {
        extensions_end = length;  // Truncated, but try to parse anyway
    }
    
    // Parse extensions to find SNI
    while (offset + 4 <= extensions_end) {
        uint16_t extension_type = readUint16BE(payload + offset);
        uint16_t extension_length = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (offset + extension_length > extensions_end) break;
        
        if (extension_type == EXTENSION_SNI) {
            // SNI extension found
            // Structure:
            //   SNI List Length (2 bytes)
            //   SNI Type (1 byte) - 0x00 for hostname
            //   SNI Length (2 bytes)
            //   SNI Value (variable)
            
            if (extension_length < 5) break;
            
            uint16_t sni_list_length = readUint16BE(payload + offset);
            if (sni_list_length < 3) break;
            
            uint8_t sni_type = payload[offset + 2];
            uint16_t sni_length = readUint16BE(payload + offset + 3);
            
            if (sni_type != SNI_TYPE_HOSTNAME) break;
            if (sni_length > extension_length - 5) break;
            
            // Extract the hostname
            std::string sni(reinterpret_cast<const char*>(payload + offset + 5), sni_length);
            return sni;
        }
        
        offset += extension_length;
    }
    
    return std::nullopt;
}

std::vector<std::pair<uint16_t, std::string>> SNIExtractor::extractExtensions(
    const uint8_t* payload, size_t length) {
    
    (void)payload;
    (void)length;
    
    std::vector<std::pair<uint16_t, std::string>> extensions;
    
    // Similar parsing logic as extract(), but collect all extensions
    // ... (abbreviated for brevity)
    
    return extensions;
}

// ============================================================================
// HTTP Host Header Extractor Implementation
// ============================================================================

bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (length < 4) return false;
    
    // Check for common HTTP methods
    const char* methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
    
    for (const char* method : methods) {
        if (std::memcmp(payload, method, 4) == 0) {
            return true;
        }
    }
    
    return false;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isHTTPRequest(payload, length)) {
        return std::nullopt;
    }
    
    // Search for "Host: " header
    const size_t host_header_len = 6;
    
    for (size_t i = 0; i + host_header_len < length; i++) {
        // Check for header (case-insensitive "host:")
        if ((payload[i] == 'H' || payload[i] == 'h') &&
            (payload[i+1] == 'o' || payload[i+1] == 'O') &&
            (payload[i+2] == 's' || payload[i+2] == 'S') &&
            (payload[i+3] == 't' || payload[i+3] == 'T') &&
            payload[i+4] == ':') {
            
            // Skip "Host:" and any whitespace
            size_t start = i + 5;
            while (start < length && (payload[start] == ' ' || payload[start] == '\t')) {
                start++;
            }
            
            // Find end of line
            size_t end = start;
            while (end < length && payload[end] != '\r' && payload[end] != '\n') {
                end++;
            }
            
            if (end > start) {
                std::string host(reinterpret_cast<const char*>(payload + start), end - start);
                
                // Remove port if present
                size_t colon_pos = host.find(':');
                if (colon_pos != std::string::npos) {
                    host = host.substr(0, colon_pos);
                }
                
                return host;
            }
        }
    }
    
    return std::nullopt;
}

// ============================================================================
// DNS Extractor Implementation
// ============================================================================

bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    // Minimum DNS header is 12 bytes
    if (length < 12) return false;
    
    // Check QR bit (byte 2, bit 7) - should be 0 for query
    uint8_t flags = payload[2];
    if (flags & 0x80) return false;  // This is a response, not a query
    
    // Check QDCOUNT (bytes 4-5) - should be > 0
    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    if (qdcount == 0) return false;
    
    return true;
}

std::optional<std::string> DNSExtractor::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) {
        return std::nullopt;
    }
    
    // DNS query starts at byte 12
    size_t offset = 12;
    std::string domain;
    
    while (offset < length) {
        uint8_t label_length = payload[offset];
        
        if (label_length == 0) {
            // End of domain name
            break;
        }
        
        if (label_length > 63) {
            // Compression pointer or invalid
            break;
        }
        
        offset++;
        if (offset + label_length > length) break;
        
        if (!domain.empty()) {
            domain += '.';
        }
        domain += std::string(reinterpret_cast<const char*>(payload + offset), label_length);
        offset += label_length;
    }
    
    return domain.empty() ? std::nullopt : std::optional<std::string>(domain);
}

// ============================================================================
// DNS Response Parsing — extract domain + resolved IPv4 addresses
// ============================================================================

bool DNSExtractor::isDNSResponse(const uint8_t* payload, size_t length) {
    if (length < 12) return false;

    // QR bit (byte 2, bit 7) — 1 for response
    uint8_t flags = payload[2];
    if (!(flags & 0x80)) return false;  // not a response

    // ANCOUNT > 0 (bytes 6-7)
    uint16_t ancount = (static_cast<uint16_t>(payload[6]) << 8) | payload[7];
    return ancount > 0;
}

// Helper: skip a DNS name (possibly compressed) and return new offset.
// Returns 0 on error.
static size_t skipDNSName(const uint8_t* payload, size_t length, size_t offset) {
    size_t pos = offset;
    bool jumped = false;
    int safety = 0;

    while (pos < length && safety++ < 128) {
        uint8_t label_len = payload[pos];

        if (label_len == 0) {
            // end of name
            if (!jumped) return pos + 1;
            else return offset + 2;  // compression pointer is 2 bytes
        }

        if ((label_len & 0xC0) == 0xC0) {
            // compression pointer — 2 bytes total
            if (!jumped) offset = pos;
            if (pos + 1 >= length) return 0;
            uint16_t ptr = ((label_len & 0x3F) << 8) | payload[pos + 1];
            pos = ptr;
            jumped = true;
            continue;
        }

        pos += 1 + label_len;
    }

    return 0;  // error
}

// Helper: read a DNS name (with compression) into a string.
static std::string readDNSName(const uint8_t* payload, size_t length, size_t offset) {
    std::string name;
    size_t pos = offset;
    int safety = 0;

    while (pos < length && safety++ < 128) {
        uint8_t label_len = payload[pos];

        if (label_len == 0) break;

        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= length) break;
            uint16_t ptr = ((label_len & 0x3F) << 8) | payload[pos + 1];
            pos = ptr;
            continue;
        }

        pos++;
        if (pos + label_len > length) break;

        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(payload + pos), label_len);
        pos += label_len;
    }

    return name;
}

std::optional<DNSExtractor::DNSAnswer> DNSExtractor::extractResponse(
        const uint8_t* payload, size_t length) {

    if (!isDNSResponse(payload, length)) return std::nullopt;

    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    uint16_t ancount = (static_cast<uint16_t>(payload[6]) << 8) | payload[7];

    // Read the queried domain from the question section
    size_t offset = 12;
    std::string domain = readDNSName(payload, length, offset);

    // Skip over all question entries
    for (uint16_t i = 0; i < qdcount && offset < length; i++) {
        offset = skipDNSName(payload, length, offset);
        if (offset == 0 || offset + 4 > length) return std::nullopt;
        offset += 4;  // QTYPE (2) + QCLASS (2)
    }

    // Parse answer RRs to find A records (type 1)
    DNSAnswer answer;
    answer.domain = domain;

    for (uint16_t i = 0; i < ancount && offset < length; i++) {
        // Skip name
        size_t name_end = skipDNSName(payload, length, offset);
        if (name_end == 0 || name_end + 10 > length) break;
        offset = name_end;

        uint16_t rtype  = (static_cast<uint16_t>(payload[offset]) << 8) | payload[offset + 1];
        // uint16_t rclass = (static_cast<uint16_t>(payload[offset + 2]) << 8) | payload[offset + 3];
        // uint32_t ttl    = ...;
        uint16_t rdlength = (static_cast<uint16_t>(payload[offset + 8]) << 8) | payload[offset + 9];
        offset += 10;

        if (offset + rdlength > length) break;

        if (rtype == 1 && rdlength == 4) {
            // A record — 4-byte IPv4 address
            // Store in host byte order (little-endian on x86) to match
            // how FiveTuple stores IPs parsed via the DPI engine.
            uint32_t ip = static_cast<uint32_t>(payload[offset])
                        | (static_cast<uint32_t>(payload[offset + 1]) << 8)
                        | (static_cast<uint32_t>(payload[offset + 2]) << 16)
                        | (static_cast<uint32_t>(payload[offset + 3]) << 24);
            answer.ips.push_back(ip);
        }

        offset += rdlength;
    }

    if (answer.domain.empty()) return std::nullopt;
    return answer;
}

// ============================================================================
// QUIC SNI Extractor (simplified)
// ============================================================================

bool QUICSNIExtractor::isQUICInitial(const uint8_t* payload, size_t length) {
    if (length < 5) return false;
    
    // QUIC long header starts with 1 bit set (form bit)
    // and the type should be Initial (0x00)
    uint8_t first_byte = payload[0];
    
    // Long header form
    if ((first_byte & 0x80) == 0) return false;
    
    // Check for QUIC version (bytes 1-4)
    // Common versions: 0x00000001 (v1), 0xff000000+ (drafts)
    // We'll be lenient here
    
    return true;
}

std::optional<std::string> QUICSNIExtractor::extract(const uint8_t* payload, size_t length) {
    // QUIC Initial packets contain the TLS Client Hello inside CRYPTO frames
    // This is complex to parse properly due to QUIC framing
    // For now, we'll do a simplified search for the SNI extension pattern
    
    if (!isQUICInitial(payload, length)) {
        return std::nullopt;
    }
    
    // Search for TLS Client Hello pattern within the QUIC packet
    // Look for the handshake type byte followed by SNI extension
    for (size_t i = 0; i + 50 < length; i++) {
        if (payload[i] == 0x01) {  // Client Hello handshake type
            // Try to extract SNI starting from here
            auto result = SNIExtractor::extract(payload + i - 5, length - i + 5);
            if (result) return result;
        }
    }
    
    return std::nullopt;
}

} // namespace DPI
