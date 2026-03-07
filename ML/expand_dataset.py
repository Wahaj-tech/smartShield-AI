"""
Generate additional training data for underrepresented categories
and add more diverse domains to improve model generalization.
"""
import csv
import random
import os

random.seed(42)

# Define domain-category mappings for expansion
DOMAIN_CATEGORY = {
    # ecommerce - currently only 13 samples
    "amazon.com": "ecommerce",
    "ebay.com": "ecommerce",
    "shopify.com": "ecommerce",
    "etsy.com": "ecommerce",
    "walmart.com": "ecommerce",
    "alibaba.com": "ecommerce",
    "flipkart.com": "ecommerce",
    "target.com": "ecommerce",
    "bestbuy.com": "ecommerce",
    "wish.com": "ecommerce",
    "aliexpress.com": "ecommerce",
    "myntra.com": "ecommerce",
    "zalando.com": "ecommerce",
    "rakuten.com": "ecommerce",
    # productivity - currently only 4 samples
    "notion.so": "productivity",
    "trello.com": "productivity",
    "asana.com": "productivity",
    "monday.com": "productivity",
    "todoist.com": "productivity",
    "clickup.com": "productivity",
    "airtable.com": "productivity",
    "basecamp.com": "productivity",
    "jira.atlassian.com": "productivity",
    "linear.app": "productivity",
    "miro.com": "productivity",
    "figma.com": "productivity",
    "canva.com": "productivity",
    "zoom.us": "productivity",
    "teams.microsoft.com": "productivity",
    # cloud_cdn - currently only 17 samples
    "akamai.net": "cloud_cdn",
    "fastly.com": "cloud_cdn",
    "bunnycdn.com": "cloud_cdn",
    "cdn77.com": "cloud_cdn",
    "maxcdn.com": "cloud_cdn",
    "stackpath.com": "cloud_cdn",
    "keycdn.com": "cloud_cdn",
    "limelight.com": "cloud_cdn",
    "azureedge.net": "cloud_cdn",
    "edgecastcdn.net": "cloud_cdn",
    # development - currently 31 samples
    "stackoverflow.com": "development",
    "gitlab.com": "development",
    "bitbucket.org": "development",
    "npmjs.com": "development",
    "pypi.org": "development",
    "docker.com": "development",
    "heroku.com": "development",
    "vercel.com": "development",
    "netlify.com": "development",
    "digitalocean.com": "development",
    "replit.com": "development",
    "codepen.io": "development",
    "codesandbox.io": "development",
    "jsfiddle.net": "development",
    "readthedocs.io": "development",
    # messaging - currently 54 samples
    "signal.org": "messaging",
    "viber.com": "messaging",
    "wechat.com": "messaging",
    "line.me": "messaging",
    "messenger.com": "messaging",
    "groupme.com": "messaging",
    "element.io": "messaging",
    "matrix.org": "messaging",
    # streaming - add more variety
    "hulu.com": "streaming",
    "disneyplus.com": "streaming",
    "primevideo.com": "streaming",
    "hbomax.com": "streaming",
    "peacocktv.com": "streaming",
    "crunchyroll.com": "streaming",
    "dazn.com": "streaming",
    "tubi.tv": "streaming",
    "twitch.tv": "streaming",
    "dailymotion.com": "streaming",
    "soundcloud.com": "streaming",
    "pandora.com": "streaming",
    "jiosaavn.com": "streaming",
    "audible.com": "streaming",
    # social_media - add more variety
    "tiktok.com": "social_media",
    "pinterest.com": "social_media",
    "tumblr.com": "social_media",
    "mastodon.social": "social_media",
    "threads.net": "social_media",
    "bluesky.app": "social_media",
    "quora.com": "social_media",
    "medium.com": "social_media",
    # search
    "duckduckgo.com": "search",
    "yahoo.com": "search",
    "yandex.com": "search",
    "baidu.com": "search",
    "ecosia.org": "search",
    "startpage.com": "search",
    # ai_tool - more variety
    "gemini.google.com": "ai_tool",
    "huggingface.co": "ai_tool",
    "cohere.ai": "ai_tool",
    "midjourney.com": "ai_tool",
    "stability.ai": "ai_tool",
    "replicate.com": "ai_tool",
    "deepmind.google": "ai_tool",
    "jasper.ai": "ai_tool",
    "copy.ai": "ai_tool",
    # adult - more variety
    "xvideos.com": "adult",
    "redtube.com": "adult",
    "youporn.com": "adult",
    "spankbang.com": "adult",
    "erome.com": "adult",
    # writing_assistant - more variety
    "hemingwayapp.com": "writing_assistant",
    "prowritingaid.com": "writing_assistant",
    "scribens.com": "writing_assistant",
    "languagetool.org": "writing_assistant",
    "writesonic.com": "writing_assistant",
    "rytr.me": "writing_assistant",
    "sudowrite.com": "writing_assistant",
    "overleaf.com": "writing_assistant",
    # other
    "wikipedia.org": "other",
    "bbc.com": "other",
    "cnn.com": "other",
    "nytimes.com": "other",
    "reuters.com": "other",
    "weather.com": "other",
    "craigslist.org": "other",
    "imgur.com": "other",
}

# Traffic profile templates per category (packet_count_range, avg_pkt_size_range,
# flow_dur_range, pps_range, bps_range)
TRAFFIC_PROFILES = {
    "ecommerce": {
        "short": (10, 40, 150, 400, 0.5, 5, 5, 30, 500, 5000),
        "medium": (40, 120, 200, 600, 5, 30, 3, 15, 1000, 10000),
        "long": (100, 300, 300, 800, 30, 120, 2, 10, 1500, 15000),
    },
    "productivity": {
        "short": (8, 30, 150, 350, 0.5, 5, 5, 25, 500, 4000),
        "medium": (30, 100, 200, 500, 5, 30, 3, 12, 800, 8000),
        "long": (80, 250, 150, 400, 30, 120, 2, 8, 500, 5000),
    },
    "cloud_cdn": {
        "short": (5, 20, 100, 300, 0.05, 1, 20, 200, 2000, 50000),
        "medium": (15, 60, 200, 600, 1, 10, 5, 40, 1000, 20000),
        "long": (50, 200, 300, 1000, 10, 60, 3, 15, 2000, 30000),
    },
    "development": {
        "short": (8, 30, 150, 400, 0.5, 5, 5, 30, 500, 6000),
        "medium": (30, 100, 200, 500, 3, 20, 3, 15, 1000, 10000),
        "long": (80, 300, 250, 700, 20, 120, 2, 10, 1000, 8000),
    },
    "messaging": {
        "short": (5, 25, 100, 300, 0.3, 3, 5, 30, 300, 4000),
        "medium": (20, 80, 150, 350, 3, 20, 3, 15, 500, 5000),
        "long": (60, 200, 100, 250, 20, 120, 2, 8, 200, 2000),
    },
    "streaming": {
        "short": (20, 60, 300, 800, 1, 5, 10, 40, 3000, 20000),
        "medium": (80, 300, 500, 1200, 10, 60, 5, 20, 5000, 40000),
        "long": (200, 1000, 800, 1500, 60, 300, 3, 15, 8000, 60000),
    },
    "social_media": {
        "short": (10, 40, 150, 400, 0.5, 5, 5, 30, 500, 6000),
        "medium": (40, 150, 200, 600, 5, 30, 3, 15, 1000, 12000),
        "long": (100, 400, 300, 800, 30, 120, 2, 10, 1500, 10000),
    },
    "search": {
        "short": (8, 25, 150, 350, 0.05, 2, 10, 200, 1000, 40000),
        "medium": (20, 60, 120, 300, 2, 10, 4, 20, 500, 8000),
        "long": (40, 120, 100, 250, 10, 60, 2, 8, 200, 3000),
    },
    "ai_tool": {
        "short": (8, 25, 200, 400, 0.05, 2, 20, 150, 2000, 40000),
        "medium": (30, 100, 150, 400, 3, 15, 5, 20, 1000, 10000),
        "long": (80, 350, 100, 300, 10, 60, 3, 15, 500, 6000),
    },
    "adult": {
        "short": (8, 25, 200, 500, 0.5, 5, 5, 30, 1000, 8000),
        "medium": (30, 120, 400, 1000, 5, 30, 3, 15, 3000, 25000),
        "long": (100, 500, 600, 1400, 30, 180, 2, 10, 5000, 40000),
    },
    "writing_assistant": {
        "short": (8, 25, 150, 350, 0.5, 5, 5, 25, 500, 4000),
        "medium": (25, 80, 120, 300, 3, 15, 4, 15, 500, 6000),
        "long": (60, 200, 100, 250, 15, 60, 2, 10, 300, 4000),
    },
    "other": {
        "short": (5, 25, 100, 400, 0.05, 3, 10, 200, 500, 30000),
        "medium": (20, 80, 150, 500, 3, 20, 3, 15, 500, 8000),
        "long": (60, 200, 100, 350, 20, 120, 1, 8, 200, 4000),
    },
}


def gen_row(domain, category, profile):
    """Generate one synthetic flow row from a traffic profile."""
    pc_lo, pc_hi, aps_lo, aps_hi, fd_lo, fd_hi, pps_lo, pps_hi, bps_lo, bps_hi = profile
    pc = random.randint(pc_lo, pc_hi)
    aps = round(random.uniform(aps_lo, aps_hi), 1)
    fd = round(random.uniform(fd_lo, fd_hi), 3)
    pps = round(random.uniform(pps_lo, pps_hi), 1)
    bps = round(random.uniform(bps_lo, bps_hi), 1)
    return [domain, "HTTPS", pc, aps, fd, pps, bps, category]


def main():
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "dpi-engine", "data", "flow_dataset.csv",
    )

    new_rows = []
    for domain, category in DOMAIN_CATEGORY.items():
        profiles = TRAFFIC_PROFILES[category]
        # Generate 8 rows per domain (mix of short/medium/long flows)
        for profile_name, profile in profiles.items():
            count = 3 if profile_name == "medium" else 2
            for _ in range(count):
                new_rows.append(gen_row(domain, category, profile))
        # Add 1 TCP variant for some
        if random.random() < 0.3:
            p = profiles["short"]
            row = gen_row(domain, category, p)
            row[1] = "TCP"
            new_rows.append(row)

    # Append to existing CSV
    with open(data_path, "a", newline="") as f:
        writer = csv.writer(f)
        for row in new_rows:
            writer.writerow(row)

    print(f"Added {len(new_rows)} new training rows to {data_path}")


if __name__ == "__main__":
    main()
