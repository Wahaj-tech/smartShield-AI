// ── Data formatting utilities ───────────────────────────────────────────────

/**
 * Format a number with commas: 175668 → "175,668"
 */
export function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

/**
 * Map a raw category string to a human-readable label.
 */
export function categoryLabel(cat: string): string {
  const labels: Record<string, string> = {
    ai_tool: 'AI Tools',
    writing_assistant: 'Writing Assistant',
    social_media: 'Social Media',
    messaging: 'Messaging',
    streaming: 'Streaming',
    search: 'Search',
    development: 'Development',
    ecommerce: 'E-Commerce',
    productivity: 'Productivity',
    cloud_cdn: 'Cloud / CDN',
    adult: 'Adult',
    other: 'Other',
  };
  return labels[cat] ?? cat;
}

/**
 * Category → color mapping for charts.
 */
export function categoryColor(cat: string): string {
  const colors: Record<string, string> = {
    ai_tool: '#EF4444',
    writing_assistant: '#8B5CF6',
    social_media: '#F59E0B',
    messaging: '#10B981',
    streaming: '#06B6D4',
    search: '#6366F1',
    development: '#3B82F6',
    ecommerce: '#F97316',
    productivity: '#14B8A6',
    cloud_cdn: '#94A3B8',
    adult: '#DC2626',
    other: '#64748B',
  };
  return colors[cat] ?? '#64748B';
}

/**
 * Map an AI domain to a friendly tool name.
 */
const AI_DOMAIN_MAP: Record<string, string> = {
  'chatgpt.com': 'ChatGPT',
  'chat.openai.com': 'ChatGPT',
  'openai.com': 'OpenAI',
  'claude.ai': 'Claude',
  'perplexity.ai': 'Perplexity',
  'bard.google.com': 'Bard',
  'gemini.google.com': 'Gemini',
  'copilot.microsoft.com': 'Copilot',
  'githubcopilot.com': 'GitHub Copilot',
  'github.copilot': 'GitHub Copilot',
  'midjourney.com': 'Midjourney',
  'huggingface.co': 'Hugging Face',
  'replicate.com': 'Replicate',
  'writesonic.com': 'Writesonic',
  'jasper.ai': 'Jasper',
  'grammarly.com': 'Grammarly',
  'quillbot.com': 'QuillBot',
  'notion.so': 'Notion AI',
};

export function getAIToolName(domain: string): string | null {
  // Direct match
  if (AI_DOMAIN_MAP[domain]) return AI_DOMAIN_MAP[domain];
  // Partial match
  for (const [key, name] of Object.entries(AI_DOMAIN_MAP)) {
    if (domain.includes(key) || key.includes(domain)) return name;
  }
  return null;
}

/**
 * Relative time label: "2 min ago", "just now", etc.
 */
export function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffSec = Math.floor((now - then) / 1000);
  if (diffSec < 10) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} min ago`;
  const diffHr = Math.floor(diffMin / 60);
  return `${diffHr}h ago`;
}
