#include "flow_csv_writer.h"
#include "types.h"
#include <iostream>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace DPI {

// ============================================================================
// FlowCSVWriter Implementation
// ============================================================================

static const char* CSV_HEADER = "domain,protocol,packet_count,avg_packet_size,flow_duration,packets_per_second,bytes_per_second,category\n";

FlowCSVWriter& FlowCSVWriter::instance() {
    static FlowCSVWriter writer;
    return writer;
}

FlowCSVWriter::~FlowCSVWriter() {
    close();
}

bool FlowCSVWriter::open(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (is_open_) {
        file_.close();
        is_open_ = false;
    }

    // Check if file already exists and has content (to decide on header)
    bool write_header = true;
    {
        std::ifstream test(path, std::ios::ate);
        if (test.is_open() && test.tellg() > 0) {
            write_header = false;  // File exists and is non-empty
        }
    }

    file_.open(path, std::ios::out | std::ios::app);
    if (!file_.is_open()) {
        std::cerr << "[FlowCSVWriter] ERROR: Cannot open " << path << "\n";
        return false;
    }

    is_open_ = true;

    if (write_header) {
        file_ << CSV_HEADER;
        file_.flush();
    }

    std::cout << "[FlowCSVWriter] Logging flow dataset to: " << path << "\n";
    return true;
}

void FlowCSVWriter::writeRecord(const FlowRecord& record) {
    // --- Dataset Cleaning ---
    // Skip flows where both domain and sni are unknown (no useful info)
    bool domain_unknown = record.domain.empty() || record.domain == "unknown";
    bool sni_unknown    = record.sni.empty()    || record.sni == "unknown";
    if (domain_unknown && sni_unknown) {
        return;
    }

    // Skip flows with too few packets (< 5)
    if (record.packet_count < 5) {
        return;
    }

    // Skip flows with very short duration (< 0.01 seconds)
    if (record.flow_duration < 0.01) {
        return;
    }

    // --- Telemetry / Ads / Analytics noise filter ---
    // Skip domains that represent telemetry, ads, analytics, or tracking
    // infrastructure.  These pollute the ML dataset with non-user-activity.
    {
        std::string d_lower = record.domain;
        for (auto& c : d_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (d_lower.find("telemetry") != std::string::npos ||
            d_lower.find("analytics") != std::string::npos ||
            d_lower.find("tracking") != std::string::npos ||
            d_lower.find("metrics") != std::string::npos ||
            d_lower.find("ads.") != std::string::npos ||
            d_lower.find(".ads.") != std::string::npos ||
            d_lower.find("adservice") != std::string::npos ||
            d_lower.find("doubleclick") != std::string::npos ||
            d_lower.find("adsystem") != std::string::npos ||
            d_lower.find("adnxs") != std::string::npos ||
            d_lower.find("googlesyndication") != std::string::npos ||
            d_lower.find("googleadservices") != std::string::npos ||
            d_lower.find("crashlytics") != std::string::npos ||
            d_lower.find("bugsnag") != std::string::npos ||
            d_lower.find("sentry") != std::string::npos) {
            return;
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_open_) return;

    // Normalize the domain for cleaner ML labels
    std::string norm_domain = record.domain.empty() ? "unknown" : normalizeDomain(record.domain);

    // Determine category — prefer the one from AppType classification.
    // Only fall back to domain-based heuristic if it was empty or "other"/"unknown".
    std::string category = record.category;
    if (category.empty() || category == "other" || category == "unknown") {
        std::string domain_cat = domainToCategory(norm_domain);
        if (domain_cat != "other" && domain_cat != "unknown") {
            category = domain_cat;
        } else if (category.empty()) {
            category = domain_cat;
        }
    }

    // Compute derived ML features
    double packets_per_sec = record.packets_per_second;
    double bytes_per_sec   = record.bytes_per_second;
    if (packets_per_sec <= 0.0 && record.flow_duration > 0.0) {
        packets_per_sec = static_cast<double>(record.packet_count) / record.flow_duration;
    }
    if (bytes_per_sec <= 0.0 && record.flow_duration > 0.0) {
        bytes_per_sec = (record.packet_count * record.avg_packet_size) / record.flow_duration;
    }

    // Build CSV line:
    // domain,protocol,packet_count,avg_packet_size,flow_duration,packets_per_second,bytes_per_second,category
    file_ << csvEscape(norm_domain)
          << ","
          << csvEscape(record.protocol.empty() ? "unknown" : record.protocol)
          << ","
          << record.packet_count
          << ","
          << std::fixed << std::setprecision(1) << record.avg_packet_size
          << ","
          << std::fixed << std::setprecision(3) << record.flow_duration
          << ","
          << std::fixed << std::setprecision(1) << packets_per_sec
          << ","
          << std::fixed << std::setprecision(1) << bytes_per_sec
          << ","
          << csvEscape(category)
          << "\n";

    file_.flush();
}

void FlowCSVWriter::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (is_open_) {
        file_.flush();
        file_.close();
        is_open_ = false;
        std::cout << "[FlowCSVWriter] Dataset file closed.\n";
    }
}

std::string FlowCSVWriter::csvEscape(const std::string& field) {
    // If field contains comma, double-quote, or newline → wrap in quotes
    bool needs_quoting = false;
    for (char c : field) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needs_quoting = true;
            break;
        }
    }

    if (!needs_quoting) return field;

    std::string escaped = "\"";
    for (char c : field) {
        if (c == '"') escaped += "\"\"";
        else escaped += c;
    }
    escaped += "\"";
    return escaped;
}

// ============================================================================
// domainToCategory() — heuristic domain→category mapping for ML labels
// ============================================================================

std::string FlowCSVWriter::domainToCategory(const std::string& domain) {
    if (domain.empty() || domain == "unknown") return "unknown";

    // Convert to lowercase for matching
    std::string d = domain;
    for (auto& c : d) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // --- AI Cheating Tools ---
    if (d.find("chatgpt") != std::string::npos ||
        d.find("openai") != std::string::npos ||
        d.find("oaistatic") != std::string::npos ||
        d.find("oaiusercontent") != std::string::npos ||
        d.find("claude") != std::string::npos ||
        d.find("anthropic") != std::string::npos ||
        d.find("perplexity") != std::string::npos ||
        d.find("copilot") != std::string::npos ||
        d.find("gemini") != std::string::npos ||
        d.find("bard") != std::string::npos ||
        d.find("you.com") != std::string::npos ||
        d.find("poe.com") != std::string::npos ||
        d.find("writesonic") != std::string::npos) {
        return "ai_tool";
    }

    // --- Writing Assistants ---
    if (d.find("grammarly") != std::string::npos ||
        d.find("quillbot") != std::string::npos ||
        d.find("wordtune") != std::string::npos ||
        d.find("prowritingaid") != std::string::npos) {
        return "writing_assistant";
    }

    // --- Adult Content ---
    if (d.find("pornhub") != std::string::npos ||
        d.find("xvideos") != std::string::npos ||
        d.find("xnxx") != std::string::npos ||
        d.find("xhamster") != std::string::npos ||
        d.find("redtube") != std::string::npos ||
        d.find("youporn") != std::string::npos ||
        d.find("brazzers") != std::string::npos ||
        d.find("onlyfans") != std::string::npos ||
        d.find("chaturbate") != std::string::npos ||
        d.find("livejasmin") != std::string::npos ||
        d.find("stripchat") != std::string::npos ||
        d.find("cam4") != std::string::npos ||
        d.find("bongacams") != std::string::npos ||
        d.find("spankbang") != std::string::npos ||
        d.find("tube8") != std::string::npos ||
        d.find("xtube") != std::string::npos) {
        return "adult";
    }

    // --- Streaming ---
    if (d.find("youtube") != std::string::npos ||
        d.find("googlevideo") != std::string::npos ||
        d.find("ytimg") != std::string::npos ||
        d.find("netflix") != std::string::npos ||
        d.find("nflxvideo") != std::string::npos ||
        d.find("twitch") != std::string::npos ||
        d.find("hulu") != std::string::npos ||
        d.find("primevideo") != std::string::npos ||
        d.find("disneyplus") != std::string::npos ||
        d.find("spotify") != std::string::npos ||
        d.find("soundcloud") != std::string::npos ||
        d.find("deezer") != std::string::npos ||
        d.find("vimeo") != std::string::npos ||
        d.find("dailymotion") != std::string::npos ||
        d.find("crunchyroll") != std::string::npos) {
        return "streaming";
    }

    // --- Social Media ---
    if (d.find("facebook") != std::string::npos ||
        d.find("instagram") != std::string::npos ||
        d.find("cdninstagram") != std::string::npos ||
        d.find("twitter") != std::string::npos ||
        d.find("tiktok") != std::string::npos ||
        d.find("snapchat") != std::string::npos ||
        d.find("reddit") != std::string::npos ||
        d.find("redditmedia") != std::string::npos ||
        d.find("redditstatic") != std::string::npos ||
        d.find("pinterest") != std::string::npos ||
        d.find("linkedin") != std::string::npos ||
        d.find("licdn") != std::string::npos ||
        d.find("tumblr") != std::string::npos ||
        d.find("fbcdn") != std::string::npos ||
        d.find("fbsbx") != std::string::npos ||
        d.find("x.com") != std::string::npos ||
        d.find("threads.net") != std::string::npos ||
        d.find("bytedance") != std::string::npos) {
        return "social_media";
    }

    // --- Messaging ---
    if (d.find("whatsapp") != std::string::npos ||
        d.find("telegram") != std::string::npos ||
        d.find("signal.org") != std::string::npos ||
        d.find("discord") != std::string::npos ||
        d.find("discordapp") != std::string::npos ||
        d.find("slack") != std::string::npos ||
        d.find("messenger") != std::string::npos ||
        d.find("viber") != std::string::npos ||
        d.find("wechat") != std::string::npos) {
        return "messaging";
    }

    // --- Development ---
    if (d.find("github") != std::string::npos ||
        d.find("gitlab") != std::string::npos ||
        d.find("bitbucket") != std::string::npos ||
        d.find("stackoverflow") != std::string::npos ||
        d.find("stackexchange") != std::string::npos ||
        d.find("npmjs") != std::string::npos ||
        d.find("pypi") != std::string::npos ||
        d.find("docker") != std::string::npos ||
        d.find("heroku") != std::string::npos ||
        d.find("vercel") != std::string::npos ||
        d.find("netlify") != std::string::npos) {
        return "development";
    }

    // --- Search ---
    if (d.find("google") != std::string::npos ||
        d.find("bing") != std::string::npos ||
        d.find("duckduckgo") != std::string::npos ||
        d.find("yahoo") != std::string::npos ||
        d.find("baidu") != std::string::npos) {
        return "search";
    }

    // --- Productivity ---
    if (d.find("microsoft") != std::string::npos ||
        d.find("office") != std::string::npos ||
        d.find("outlook") != std::string::npos ||
        d.find("azure") != std::string::npos ||
        d.find("live.com") != std::string::npos ||
        d.find("msn") != std::string::npos) {
        return "productivity";
    }

    // --- Cloud / CDN ---
    if (d.find("cloudflare") != std::string::npos ||
        d.find("amazonaws") != std::string::npos ||
        d.find("akamai") != std::string::npos ||
        d.find("fastly") != std::string::npos ||
        d.find("cloudfront") != std::string::npos ||
        d.find("azureedge") != std::string::npos) {
        return "cloud_cdn";
    }

    // --- E-commerce ---
    if (d.find("amazon") != std::string::npos ||
        d.find("ebay") != std::string::npos ||
        d.find("shopify") != std::string::npos ||
        d.find("aliexpress") != std::string::npos ||
        d.find("etsy") != std::string::npos) {
        return "ecommerce";
    }

    // --- News ---
    if (d.find("cnn") != std::string::npos ||
        d.find("bbc") != std::string::npos ||
        d.find("reuters") != std::string::npos ||
        d.find("nytimes") != std::string::npos ||
        d.find("theguardian") != std::string::npos ||
        d.find("aljazeera") != std::string::npos) {
        return "news";
    }

    // --- Video Conferencing ---
    if (d.find("zoom") != std::string::npos ||
        d.find("teams") != std::string::npos ||
        d.find("meet.google") != std::string::npos ||
        d.find("webex") != std::string::npos) {
        return "video_conferencing";
    }

    // --- Gaming ---
    if (d.find("steam") != std::string::npos ||
        d.find("epicgames") != std::string::npos ||
        d.find("riot") != std::string::npos ||
        d.find("blizzard") != std::string::npos ||
        d.find("xbox") != std::string::npos ||
        d.find("playstation") != std::string::npos) {
        return "gaming";
    }

    // --- Education ---
    if (d.find("coursera") != std::string::npos ||
        d.find("udemy") != std::string::npos ||
        d.find("edx") != std::string::npos ||
        d.find("khanacademy") != std::string::npos ||
        d.find(".edu") != std::string::npos) {
        return "education";
    }

    // --- Apple ecosystem ---
    if (d.find("apple") != std::string::npos ||
        d.find("icloud") != std::string::npos ||
        d.find("itunes") != std::string::npos) {
        return "productivity";
    }

    return "other";
}

} // namespace DPI
