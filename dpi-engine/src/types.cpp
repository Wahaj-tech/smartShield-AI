#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <vector>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:           return "Unknown";
        case AppType::HTTP:              return "HTTP";
        case AppType::HTTPS:             return "HTTPS";
        case AppType::DNS:               return "DNS";
        case AppType::TLS:               return "TLS";
        case AppType::QUIC:              return "QUIC";
        case AppType::GOOGLE:            return "Google";
        case AppType::FACEBOOK:          return "Facebook";
        case AppType::YOUTUBE:           return "YouTube";
        case AppType::TWITTER:           return "Twitter/X";
        case AppType::INSTAGRAM:         return "Instagram";
        case AppType::NETFLIX:           return "Netflix";
        case AppType::AMAZON:            return "Amazon";
        case AppType::MICROSOFT:         return "Microsoft";
        case AppType::APPLE:             return "Apple";
        case AppType::WHATSAPP:          return "WhatsApp";
        case AppType::TELEGRAM:          return "Telegram";
        case AppType::TIKTOK:            return "TikTok";
        case AppType::SPOTIFY:           return "Spotify";
        case AppType::ZOOM:              return "Zoom";
        case AppType::DISCORD:           return "Discord";
        case AppType::GITHUB:            return "GitHub";
        case AppType::CLOUDFLARE:        return "Cloudflare";
        case AppType::CHATGPT:           return "ChatGPT";
        case AppType::AI_TOOL:           return "AI_TOOL";
        case AppType::WRITING_ASSISTANT: return "WRITING_ASSISTANT";
        case AppType::SOCIAL_MEDIA:      return "SOCIAL_MEDIA";
        case AppType::MESSAGING:         return "MESSAGING";
        case AppType::STREAMING:         return "STREAMING";
        case AppType::ADULT:             return "ADULT";
        case AppType::SEARCH:            return "SEARCH";
        case AppType::PRODUCTIVITY:      return "PRODUCTIVITY";
        default:                         return "Unknown";
    }
}

// Convert AppType to ML category string
std::string appTypeToCategory(AppType type) {
    switch (type) {
        case AppType::AI_TOOL:
        case AppType::CHATGPT:
            return "ai_tool";
        case AppType::WRITING_ASSISTANT:
            return "writing_assistant";
        case AppType::SOCIAL_MEDIA:
        case AppType::FACEBOOK:
        case AppType::INSTAGRAM:
        case AppType::TWITTER:
        case AppType::TIKTOK:
            return "social_media";
        case AppType::MESSAGING:
        case AppType::WHATSAPP:
        case AppType::TELEGRAM:
        case AppType::DISCORD:
            return "messaging";
        case AppType::STREAMING:
        case AppType::YOUTUBE:
        case AppType::NETFLIX:
        case AppType::SPOTIFY:
            return "streaming";
        case AppType::ADULT:
            return "adult";
        case AppType::SEARCH:
        case AppType::GOOGLE:
            return "search";
        case AppType::PRODUCTIVITY:
        case AppType::MICROSOFT:
            return "productivity";
        case AppType::AMAZON:
            return "ecommerce";
        case AppType::APPLE:
            return "productivity";
        case AppType::GITHUB:
            return "development";
        case AppType::ZOOM:
            return "video_conferencing";
        case AppType::CLOUDFLARE:
            return "cloud_cdn";
        case AppType::HTTP:
        case AppType::HTTPS:
        case AppType::TLS:
        case AppType::QUIC:
        case AppType::DNS:
            return "other";
        default:
            return "unknown";
    }
}

// ============================================================================
// Domain Normalization
// ============================================================================
// Strips CDN/infrastructure prefixes and extracts the root domain.
// Examples:
//   cdn.you.com                          → you.com
//   edge-chat.facebook.com               → facebook.com
//   pplx-next-static-public.perplexity.ai → perplexity.ai
//   ws.chatgpt.com                       → chatgpt.com
//   graph.instagram.com                  → instagram.com
//   rr5---sn-abc.googlevideo.com         → googlevideo.com
// ============================================================================

// Known second-level TLDs where the "root" is actually 3 parts
static const std::vector<std::string> MULTI_PART_TLDS = {
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tw",
    "org.uk", "net.au", "ac.uk", "gov.uk"
};

static inline bool endsWith(const std::string& s, const std::string& suffix) {
    if (suffix.size() > s.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// ============================================================================
// CDN / Infrastructure domain → canonical service mapping
// ============================================================================
// Some services use entirely separate domains for their CDN or API
// infrastructure.  These are top-level domains (2 labels) that cannot
// be simplified by stripping subdomains — they must be explicitly
// mapped to the parent service.
// ============================================================================
struct CDNMapping {
    const char* cdn_domain;   // what we see in DNS / SNI
    const char* service;      // what we want in the dataset
};

static const CDNMapping CDN_MAPPINGS[] = {
    // --- Meta / Facebook family ---
    {"fbcdn.net",         "facebook.com"},
    {"fbsbx.com",         "facebook.com"},
    {"facebook.net",      "facebook.com"},
    {"fb.com",            "facebook.com"},
    {"cdninstagram.com",  "instagram.com"},
    {"ig.me",             "instagram.com"},

    // --- Reddit ---
    {"redditmedia.com",   "reddit.com"},
    {"redditstatic.com",  "reddit.com"},
    {"redd.it",           "reddit.com"},
    {"redditmedia.net",   "reddit.com"},

    // --- Twitter / X ---
    {"twimg.com",         "twitter.com"},
    {"t.co",              "twitter.com"},
    {"twitpic.com",       "twitter.com"},

    // --- Google / YouTube ---
    {"googlevideo.com",   "youtube.com"},
    {"ytimg.com",         "youtube.com"},
    {"youtu.be",          "youtube.com"},
    {"ggpht.com",         "youtube.com"},
    {"gstatic.com",       "google.com"},
    {"googleapis.com",    "google.com"},
    {"gvt1.com",          "google.com"},

    // --- OpenAI / ChatGPT ---
    {"oaistatic.com",     "chatgpt.com"},
    {"oaiusercontent.com","chatgpt.com"},
    {"openaiapi.com",     "openai.com"},

    // --- Netflix ---
    {"nflxvideo.net",     "netflix.com"},
    {"nflximg.net",       "netflix.com"},
    {"nflximg.com",       "netflix.com"},
    {"nflxext.com",       "netflix.com"},

    // --- Spotify ---
    {"scdn.co",           "spotify.com"},
    {"spotifycdn.com",    "spotify.com"},

    // --- Snapchat ---
    {"snap.com",          "snapchat.com"},
    {"snapkit.co",        "snapchat.com"},

    // --- TikTok ---
    {"tiktokcdn.com",     "tiktok.com"},
    {"musical.ly",        "tiktok.com"},
    {"bytedance.com",     "tiktok.com"},

    // --- WhatsApp ---
    {"whatsapp.net",      "whatsapp.com"},
    {"wa.me",             "whatsapp.com"},

    // --- Discord ---
    {"discordapp.com",    "discord.com"},
    {"discordapp.net",    "discord.com"},
    {"discord.gg",        "discord.com"},

    // --- LinkedIn ---
    {"licdn.com",         "linkedin.com"},

    // --- Apple ---
    {"mzstatic.com",      "apple.com"},

    // --- Perplexity ---
    {"pplx.ai",           "perplexity.ai"},

    // --- Anthropic ---
    {"claude.ai",         "claude.ai"},

    // --- GitHub Copilot / VS Code ---
    {"vscode-cdn.net",    "githubcopilot.com"},
    {"vscode.dev",        "githubcopilot.com"},

    // sentinel
    {nullptr, nullptr}
};

std::string normalizeDomain(const std::string& domain) {
    if (domain.empty() || domain == "unknown") return domain;

    // Convert to lowercase
    std::string d = domain;
    std::transform(d.begin(), d.end(), d.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Remove trailing dot if present
    if (!d.empty() && d.back() == '.') {
        d.pop_back();
    }

    // Split into labels
    std::vector<std::string> labels;
    std::istringstream iss(d);
    std::string label;
    while (std::getline(iss, label, '.')) {
        if (!label.empty()) {
            labels.push_back(label);
        }
    }

    // Extract root domain first (last 2 labels, or 3 for multi-part TLDs)
    std::string root;
    if (labels.size() <= 2) {
        root = d;
    } else {
        // Check for multi-part TLDs (e.g. co.uk)
        std::string last_two = labels[labels.size() - 2] + "." + labels[labels.size() - 1];
        bool is_multi = false;
        for (const auto& mpt : MULTI_PART_TLDS) {
            if (last_two == mpt) {
                root = labels[labels.size() - 3] + "." + last_two;
                is_multi = true;
                break;
            }
        }
        if (!is_multi) {
            root = labels[labels.size() - 2] + "." + labels[labels.size() - 1];
        }
    }

    // Apply CDN-to-service mapping on the root domain
    for (const CDNMapping* m = CDN_MAPPINGS; m->cdn_domain; ++m) {
        if (root == m->cdn_domain) {
            return m->service;
        }
    }

    return root;
}

// ============================================================================
// SNI / Domain → AppType classification
// ============================================================================
// Checks both the raw SNI and the normalized root domain to maximize detection.
// Category-based types (AI_TOOL, STREAMING, etc.) are preferred over
// legacy per-app types when applicable.
// ============================================================================

AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Also get normalized root domain for matching
    std::string root = normalizeDomain(lower_sni);

    // =====================================================================
    // 1. AI CHEATING TOOLS  →  AI_TOOL
    // =====================================================================
    // ChatGPT / OpenAI
    if (lower_sni.find("chatgpt") != std::string::npos ||
        lower_sni.find("openai") != std::string::npos ||
        lower_sni.find("oaiusercontent") != std::string::npos ||
        lower_sni.find("oaistatic") != std::string::npos ||
        lower_sni.find("openaiapi") != std::string::npos) {
        return AppType::AI_TOOL;
    }
    // Claude / Anthropic
    if (lower_sni.find("claude.ai") != std::string::npos ||
        lower_sni.find("anthropic") != std::string::npos) {
        return AppType::AI_TOOL;
    }
    // Perplexity
    if (lower_sni.find("perplexity") != std::string::npos) {
        return AppType::AI_TOOL;
    }
    // Microsoft Copilot (check before generic Microsoft)
    if (lower_sni.find("copilot") != std::string::npos) {
        return AppType::AI_TOOL;
    }
    // Gemini / Bard (Google AI — check before generic Google)
    if (lower_sni.find("gemini") != std::string::npos ||
        lower_sni.find("bard") != std::string::npos) {
        return AppType::AI_TOOL;
    }
    // You.com
    if (root == "you.com" ||
        lower_sni.find("you.com") != std::string::npos) {
        return AppType::AI_TOOL;
    }
    // Poe.com
    if (root == "poe.com" ||
        lower_sni.find("poe.com") != std::string::npos) {
        return AppType::AI_TOOL;
    }
    // WriteSonic
    if (lower_sni.find("writesonic") != std::string::npos) {
        return AppType::AI_TOOL;
    }
    // GitHub Copilot (vscode-cdn already mapped via normalization)
    if (lower_sni.find("githubcopilot") != std::string::npos ||
        lower_sni.find("vscode-cdn") != std::string::npos) {
        return AppType::AI_TOOL;
    }

    // =====================================================================
    // 2. WRITING ASSISTANTS  →  WRITING_ASSISTANT
    // =====================================================================
    if (lower_sni.find("grammarly") != std::string::npos) {
        return AppType::WRITING_ASSISTANT;
    }
    if (lower_sni.find("quillbot") != std::string::npos) {
        return AppType::WRITING_ASSISTANT;
    }
    if (lower_sni.find("wordtune") != std::string::npos) {
        return AppType::WRITING_ASSISTANT;
    }
    if (lower_sni.find("prowritingaid") != std::string::npos) {
        return AppType::WRITING_ASSISTANT;
    }

    // =====================================================================
    // 3. ADULT CONTENT  →  ADULT
    // =====================================================================
    if (lower_sni.find("pornhub") != std::string::npos ||
        lower_sni.find("xvideos") != std::string::npos ||
        lower_sni.find("xnxx") != std::string::npos ||
        lower_sni.find("xhamster") != std::string::npos ||
        lower_sni.find("redtube") != std::string::npos ||
        lower_sni.find("youporn") != std::string::npos ||
        lower_sni.find("brazzers") != std::string::npos ||
        lower_sni.find("onlyfans") != std::string::npos ||
        lower_sni.find("chaturbate") != std::string::npos ||
        lower_sni.find("livejasmin") != std::string::npos ||
        lower_sni.find("stripchat") != std::string::npos ||
        lower_sni.find("cam4") != std::string::npos ||
        lower_sni.find("bongacams") != std::string::npos ||
        lower_sni.find("spankbang") != std::string::npos ||
        lower_sni.find("tube8") != std::string::npos ||
        lower_sni.find("xtube") != std::string::npos) {
        return AppType::ADULT;
    }

    // =====================================================================
    // 4. STREAMING  →  STREAMING
    // =====================================================================
    // YouTube (including googlevideo CDN)
    if (lower_sni.find("youtube") != std::string::npos ||
        lower_sni.find("ytimg") != std::string::npos ||
        lower_sni.find("youtu.be") != std::string::npos ||
        lower_sni.find("yt3.ggpht") != std::string::npos ||
        lower_sni.find("googlevideo") != std::string::npos) {
        return AppType::STREAMING;
    }
    // Netflix
    if (lower_sni.find("netflix") != std::string::npos ||
        lower_sni.find("nflxvideo") != std::string::npos ||
        lower_sni.find("nflximg") != std::string::npos) {
        return AppType::STREAMING;
    }
    // Spotify
    if (lower_sni.find("spotify") != std::string::npos ||
        lower_sni.find("scdn.co") != std::string::npos) {
        return AppType::STREAMING;
    }
    // Twitch
    if (lower_sni.find("twitch") != std::string::npos) {
        return AppType::STREAMING;
    }
    // Prime Video
    if (lower_sni.find("primevideo") != std::string::npos) {
        return AppType::STREAMING;
    }
    // Disney+
    if (lower_sni.find("disneyplus") != std::string::npos ||
        lower_sni.find("disney-plus") != std::string::npos) {
        return AppType::STREAMING;
    }
    // Hulu
    if (lower_sni.find("hulu") != std::string::npos) {
        return AppType::STREAMING;
    }
    // SoundCloud, Deezer, Vimeo, Dailymotion
    if (lower_sni.find("soundcloud") != std::string::npos ||
        lower_sni.find("deezer") != std::string::npos ||
        lower_sni.find("vimeo") != std::string::npos ||
        lower_sni.find("dailymotion") != std::string::npos ||
        lower_sni.find("crunchyroll") != std::string::npos) {
        return AppType::STREAMING;
    }

    // =====================================================================
    // 5. SOCIAL MEDIA  →  SOCIAL_MEDIA
    // =====================================================================
    // Facebook/Meta
    if (lower_sni.find("facebook") != std::string::npos ||
        lower_sni.find("fbcdn") != std::string::npos ||
        lower_sni.find("fb.com") != std::string::npos ||
        lower_sni.find("fbsbx") != std::string::npos ||
        lower_sni.find("meta.com") != std::string::npos ||
        lower_sni.find("facebook.net") != std::string::npos) {
        return AppType::SOCIAL_MEDIA;
    }
    // Instagram
    if (lower_sni.find("instagram") != std::string::npos ||
        lower_sni.find("cdninstagram") != std::string::npos ||
        root == "ig.me") {
        return AppType::SOCIAL_MEDIA;
    }
    // Twitter/X
    if (lower_sni.find("twitter") != std::string::npos ||
        lower_sni.find("twimg") != std::string::npos ||
        lower_sni.find("t.co") != std::string::npos) {
        return AppType::SOCIAL_MEDIA;
    }
    // x.com (must be exact domain match to avoid false positives)
    if (root == "x.com") {
        return AppType::SOCIAL_MEDIA;
    }
    // Reddit
    if (lower_sni.find("reddit") != std::string::npos ||
        lower_sni.find("redd.it") != std::string::npos ||
        lower_sni.find("redditmedia") != std::string::npos ||
        lower_sni.find("redditstatic") != std::string::npos) {
        return AppType::SOCIAL_MEDIA;
    }
    // TikTok
    if (lower_sni.find("tiktok") != std::string::npos ||
        lower_sni.find("tiktokcdn") != std::string::npos ||
        lower_sni.find("musical.ly") != std::string::npos ||
        lower_sni.find("bytedance") != std::string::npos) {
        return AppType::SOCIAL_MEDIA;
    }
    // Snapchat
    if (lower_sni.find("snapchat") != std::string::npos ||
        lower_sni.find("snap.com") != std::string::npos ||
        lower_sni.find("snapkit") != std::string::npos) {
        return AppType::SOCIAL_MEDIA;
    }
    // LinkedIn
    if (lower_sni.find("linkedin") != std::string::npos) {
        return AppType::SOCIAL_MEDIA;
    }
    // Pinterest
    if (lower_sni.find("pinterest") != std::string::npos) {
        return AppType::SOCIAL_MEDIA;
    }
    // Threads
    if (lower_sni.find("threads.net") != std::string::npos) {
        return AppType::SOCIAL_MEDIA;
    }

    // =====================================================================
    // 6. MESSAGING  →  MESSAGING
    // =====================================================================
    // WhatsApp
    if (lower_sni.find("whatsapp") != std::string::npos ||
        lower_sni.find("wa.me") != std::string::npos) {
        return AppType::MESSAGING;
    }
    // Telegram
    if (lower_sni.find("telegram") != std::string::npos ||
        lower_sni.find("t.me") != std::string::npos) {
        return AppType::MESSAGING;
    }
    // Discord
    if (lower_sni.find("discord") != std::string::npos ||
        lower_sni.find("discordapp") != std::string::npos) {
        return AppType::MESSAGING;
    }
    // Signal
    if (lower_sni.find("signal.org") != std::string::npos ||
        root == "signal.org") {
        return AppType::MESSAGING;
    }
    // Google Chat / Hangouts signaler
    if (lower_sni.find("signaler-pa") != std::string::npos) {
        return AppType::MESSAGING;
    }
    // Messenger (Facebook)
    if (lower_sni.find("messenger") != std::string::npos) {
        return AppType::MESSAGING;
    }
    // Slack
    if (lower_sni.find("slack") != std::string::npos) {
        return AppType::MESSAGING;
    }
    // Viber
    if (lower_sni.find("viber") != std::string::npos) {
        return AppType::MESSAGING;
    }
    // WeChat
    if (lower_sni.find("wechat") != std::string::npos) {
        return AppType::MESSAGING;
    }

    // =====================================================================
    // 7. SEARCH ENGINES  →  SEARCH
    // =====================================================================
    // Google (generic search — after Gemini/Bard/YouTube checks)
    if (lower_sni.find("google") != std::string::npos ||
        lower_sni.find("gstatic") != std::string::npos ||
        lower_sni.find("googleapis") != std::string::npos ||
        lower_sni.find("ggpht") != std::string::npos ||
        lower_sni.find("gvt1") != std::string::npos) {
        return AppType::SEARCH;
    }
    // Bing
    if (lower_sni.find("bing") != std::string::npos) {
        return AppType::SEARCH;
    }
    // DuckDuckGo
    if (lower_sni.find("duckduckgo") != std::string::npos) {
        return AppType::SEARCH;
    }
    // Yahoo
    if (lower_sni.find("yahoo") != std::string::npos) {
        return AppType::SEARCH;
    }

    // =====================================================================
    // 8. PRODUCTIVITY  →  PRODUCTIVITY
    // =====================================================================
    // Microsoft (generic — after Copilot check, after Bing → SEARCH)
    if (lower_sni.find("microsoft") != std::string::npos ||
        lower_sni.find("msn.com") != std::string::npos ||
        lower_sni.find("office") != std::string::npos ||
        lower_sni.find("azure") != std::string::npos ||
        lower_sni.find("live.com") != std::string::npos ||
        lower_sni.find("outlook") != std::string::npos) {
        return AppType::PRODUCTIVITY;
    }

    // Amazon (generic)
    if (lower_sni.find("amazon") != std::string::npos ||
        lower_sni.find("amazonaws") != std::string::npos ||
        lower_sni.find("aws") != std::string::npos) {
        return AppType::AMAZON;
    }

    // Apple
    if (lower_sni.find("apple") != std::string::npos ||
        lower_sni.find("icloud") != std::string::npos ||
        lower_sni.find("mzstatic") != std::string::npos ||
        lower_sni.find("itunes") != std::string::npos) {
        return AppType::APPLE;
    }

    // Zoom
    if (lower_sni.find("zoom") != std::string::npos) {
        return AppType::ZOOM;
    }

    // GitHub (but not githubcopilot — that's AI_TOOL, already caught above via "copilot")
    if (lower_sni.find("github") != std::string::npos ||
        lower_sni.find("githubusercontent") != std::string::npos) {
        return AppType::GITHUB;
    }

    // =====================================================================
    // 10. CDN / INFRASTRUCTURE — low-priority fallback
    // =====================================================================
    if (lower_sni.find("cloudflare") != std::string::npos ||
        lower_sni.find("cloudfront") != std::string::npos ||
        lower_sni.find("akamai") != std::string::npos ||
        lower_sni.find("fastly") != std::string::npos ||
        lower_sni.find("azureedge") != std::string::npos ||
        lower_sni.find("edgecastcdn") != std::string::npos) {
        return AppType::CLOUDFLARE;  // generic CDN bucket
    }

    // If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType::HTTPS;
}

} // namespace DPI
