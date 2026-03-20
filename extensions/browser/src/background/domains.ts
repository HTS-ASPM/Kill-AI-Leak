// ---------------------------------------------------------------------------
// AI Domain Database
//
// Comprehensive catalog of 50+ known AI service domains, organized by
// category. Used by the service worker to classify intercepted requests and
// by the policy engine to apply per-provider rules.
// ---------------------------------------------------------------------------

export type AICategory =
  | "chat_ai"
  | "code_ai"
  | "image_ai"
  | "audio_ai"
  | "video_ai"
  | "writing_ai"
  | "search_ai"
  | "api_endpoint"
  | "ai_platform"
  | "ai_aggregator";

export interface AIDomainEntry {
  /** Glob-free hostname (e.g. "chat.openai.com"). */
  domain: string;
  /** Human-readable provider name shown in the dashboard. */
  provider: string;
  /** Functional category. */
  category: AICategory;
  /** If true this is an API endpoint, not a web UI. */
  isAPI: boolean;
}

// ---------------------------------------------------------------------------
// Domain registry
// ---------------------------------------------------------------------------

const DOMAIN_ENTRIES: readonly AIDomainEntry[] = [
  // ---- Chat AI ----
  { domain: "chat.openai.com",           provider: "OpenAI",        category: "chat_ai",       isAPI: false },
  { domain: "chatgpt.com",               provider: "OpenAI",        category: "chat_ai",       isAPI: false },
  { domain: "claude.ai",                 provider: "Anthropic",     category: "chat_ai",       isAPI: false },
  { domain: "gemini.google.com",         provider: "Google",        category: "chat_ai",       isAPI: false },
  { domain: "aistudio.google.com",       provider: "Google",        category: "chat_ai",       isAPI: false },
  { domain: "bard.google.com",           provider: "Google",        category: "chat_ai",       isAPI: false },
  { domain: "copilot.microsoft.com",     provider: "Microsoft",     category: "chat_ai",       isAPI: false },
  { domain: "www.bing.com",              provider: "Microsoft",     category: "chat_ai",       isAPI: false },
  { domain: "poe.com",                   provider: "Quora",         category: "chat_ai",       isAPI: false },
  { domain: "perplexity.ai",             provider: "Perplexity",    category: "search_ai",     isAPI: false },
  { domain: "www.perplexity.ai",         provider: "Perplexity",    category: "search_ai",     isAPI: false },
  { domain: "labs.perplexity.ai",        provider: "Perplexity",    category: "search_ai",     isAPI: false },
  { domain: "you.com",                   provider: "You.com",       category: "search_ai",     isAPI: false },
  { domain: "character.ai",              provider: "Character.AI",  category: "chat_ai",       isAPI: false },
  { domain: "beta.character.ai",         provider: "Character.AI",  category: "chat_ai",       isAPI: false },
  { domain: "pi.ai",                     provider: "Inflection",    category: "chat_ai",       isAPI: false },
  { domain: "inflection.ai",             provider: "Inflection",    category: "chat_ai",       isAPI: false },
  { domain: "coral.cohere.com",          provider: "Cohere",        category: "chat_ai",       isAPI: false },
  { domain: "chat.mistral.ai",           provider: "Mistral",       category: "chat_ai",       isAPI: false },
  { domain: "deepseek.com",              provider: "DeepSeek",      category: "chat_ai",       isAPI: false },
  { domain: "huggingface.co",            provider: "HuggingFace",   category: "ai_platform",   isAPI: false },
  { domain: "groq.com",                  provider: "Groq",          category: "chat_ai",       isAPI: false },
  { domain: "notebooklm.google.com",     provider: "Google",        category: "chat_ai",       isAPI: false },

  // ---- Code AI ----
  { domain: "github.com",                provider: "GitHub Copilot", category: "code_ai",      isAPI: false },
  { domain: "copilot.github.com",        provider: "GitHub Copilot", category: "code_ai",      isAPI: false },
  { domain: "cursor.sh",                 provider: "Cursor",        category: "code_ai",       isAPI: false },
  { domain: "www.cursor.sh",             provider: "Cursor",        category: "code_ai",       isAPI: false },
  { domain: "replit.com",                provider: "Replit",        category: "code_ai",       isAPI: false },
  { domain: "codeium.com",              provider: "Codeium",       category: "code_ai",       isAPI: false },
  { domain: "tabnine.com",              provider: "Tabnine",       category: "code_ai",       isAPI: false },
  { domain: "sourcegraph.com",          provider: "Sourcegraph",   category: "code_ai",       isAPI: false },
  { domain: "cody.dev",                 provider: "Sourcegraph",   category: "code_ai",       isAPI: false },

  // ---- Image AI ----
  { domain: "midjourney.com",            provider: "Midjourney",    category: "image_ai",      isAPI: false },
  { domain: "www.midjourney.com",        provider: "Midjourney",    category: "image_ai",      isAPI: false },
  { domain: "stability.ai",             provider: "Stability AI",  category: "image_ai",      isAPI: false },
  { domain: "dream.ai",                 provider: "Stability AI",  category: "image_ai",      isAPI: false },
  { domain: "app.leonardo.ai",          provider: "Leonardo AI",   category: "image_ai",      isAPI: false },
  { domain: "www.imagine.art",          provider: "Imagine Art",   category: "image_ai",      isAPI: false },
  { domain: "ideogram.ai",              provider: "Ideogram",      category: "image_ai",      isAPI: false },
  { domain: "designer.microsoft.com",   provider: "Microsoft",     category: "image_ai",      isAPI: false },

  // ---- Audio AI ----
  { domain: "elevenlabs.io",             provider: "ElevenLabs",    category: "audio_ai",      isAPI: false },
  { domain: "play.ht",                  provider: "PlayHT",        category: "audio_ai",      isAPI: false },
  { domain: "murf.ai",                  provider: "Murf AI",       category: "audio_ai",      isAPI: false },
  { domain: "www.descript.com",          provider: "Descript",      category: "audio_ai",      isAPI: false },
  { domain: "suno.com",                 provider: "Suno",          category: "audio_ai",      isAPI: false },

  // ---- Video AI ----
  { domain: "runwayml.com",              provider: "Runway",        category: "video_ai",      isAPI: false },
  { domain: "app.runwayml.com",          provider: "Runway",        category: "video_ai",      isAPI: false },

  // ---- Writing AI ----
  { domain: "www.jasper.ai",             provider: "Jasper",        category: "writing_ai",    isAPI: false },
  { domain: "writesonic.com",            provider: "Writesonic",    category: "writing_ai",    isAPI: false },
  { domain: "www.copy.ai",              provider: "Copy.ai",       category: "writing_ai",    isAPI: false },
  { domain: "rytr.me",                  provider: "Rytr",          category: "writing_ai",    isAPI: false },
  { domain: "app.wordtune.com",         provider: "Wordtune",      category: "writing_ai",    isAPI: false },
  { domain: "app.grammarly.com",        provider: "Grammarly",     category: "writing_ai",    isAPI: false },

  // ---- AI Aggregators / Routers ----
  { domain: "openrouter.ai",             provider: "OpenRouter",    category: "ai_aggregator",  isAPI: false },
  { domain: "together.ai",              provider: "Together AI",   category: "ai_aggregator",  isAPI: false },
  { domain: "fireworks.ai",             provider: "Fireworks AI",  category: "ai_aggregator",  isAPI: false },
  { domain: "replicate.com",            provider: "Replicate",     category: "ai_platform",    isAPI: false },
  { domain: "ollama.com",               provider: "Ollama",        category: "ai_platform",    isAPI: false },

  // ---- API Endpoints ----
  { domain: "api.openai.com",            provider: "OpenAI",        category: "api_endpoint",  isAPI: true },
  { domain: "api.anthropic.com",         provider: "Anthropic",     category: "api_endpoint",  isAPI: true },
  { domain: "generativelanguage.googleapis.com", provider: "Google", category: "api_endpoint", isAPI: true },
  { domain: "api.cohere.ai",            provider: "Cohere",        category: "api_endpoint",  isAPI: true },
  { domain: "api.mistral.ai",           provider: "Mistral",       category: "api_endpoint",  isAPI: true },
  { domain: "api.groq.com",             provider: "Groq",          category: "api_endpoint",  isAPI: true },
  { domain: "api.together.xyz",         provider: "Together AI",   category: "api_endpoint",  isAPI: true },
  { domain: "api.fireworks.ai",         provider: "Fireworks AI",  category: "api_endpoint",  isAPI: true },
  { domain: "api.deepseek.com",         provider: "DeepSeek",      category: "api_endpoint",  isAPI: true },
  { domain: "api.replicate.com",        provider: "Replicate",     category: "api_endpoint",  isAPI: true },
  { domain: "api-inference.huggingface.co", provider: "HuggingFace", category: "api_endpoint", isAPI: true },
  { domain: "api.stability.ai",         provider: "Stability AI",  category: "api_endpoint",  isAPI: true },
  { domain: "api.elevenlabs.io",        provider: "ElevenLabs",    category: "api_endpoint",  isAPI: true },
  { domain: "api.openrouter.ai",        provider: "OpenRouter",    category: "api_endpoint",  isAPI: true },
] as const;

// ---------------------------------------------------------------------------
// Lookup indexes -- built lazily on first call
// ---------------------------------------------------------------------------

let domainMap: Map<string, AIDomainEntry> | null = null;

function ensureIndex(): Map<string, AIDomainEntry> {
  if (domainMap) return domainMap;
  domainMap = new Map();
  for (const entry of DOMAIN_ENTRIES) {
    domainMap.set(entry.domain, entry);
  }
  return domainMap;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns true if the hostname (or URL) belongs to a known AI service.
 * Accepts a full URL string or a bare hostname.
 */
export function isAIDomain(urlOrHostname: string): boolean {
  const host = extractHostname(urlOrHostname);
  return ensureIndex().has(host);
}

/** Returns the AI category for a known domain, or null. */
export function getAICategory(urlOrHostname: string): AICategory | null {
  const entry = ensureIndex().get(extractHostname(urlOrHostname));
  return entry?.category ?? null;
}

/** Returns the human-readable provider name, or null. */
export function getAIProvider(urlOrHostname: string): string | null {
  const entry = ensureIndex().get(extractHostname(urlOrHostname));
  return entry?.provider ?? null;
}

/** Returns the full domain entry, or null. */
export function getAIDomainEntry(urlOrHostname: string): AIDomainEntry | null {
  return ensureIndex().get(extractHostname(urlOrHostname)) ?? null;
}

/** Returns all registered domains for a given category. */
export function getDomainsByCategory(category: AICategory): AIDomainEntry[] {
  return DOMAIN_ENTRIES.filter((e) => e.category === category);
}

/** Returns all domain hostnames as a flat array (used for host_permissions). */
export function getAllDomains(): string[] {
  return DOMAIN_ENTRIES.map((e) => e.domain);
}

/** Returns all API endpoint domains. */
export function getAPIDomains(): AIDomainEntry[] {
  return DOMAIN_ENTRIES.filter((e) => e.isAPI);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractHostname(urlOrHostname: string): string {
  // If it looks like a URL, parse it; otherwise treat as bare hostname.
  if (urlOrHostname.includes("://")) {
    try {
      return new URL(urlOrHostname).hostname;
    } catch {
      return urlOrHostname;
    }
  }
  // Strip port if present.
  const colonIdx = urlOrHostname.indexOf(":");
  return colonIdx > 0 ? urlOrHostname.slice(0, colonIdx) : urlOrHostname;
}
