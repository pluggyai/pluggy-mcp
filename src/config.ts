/**
 * Runtime configuration loader.
 *
 * Reads Pluggy credentials from the environment. We intentionally DO NOT
 * throw at module load: an MCP stdio server must initialize the JSON-RPC
 * transport even when credentials are missing, so the host can list tools.
 * Credentials are checked lazily when a tool actually needs to call Pluggy.
 */

import 'dotenv/config';
import { logEvent } from './util/log.js';

export type PluggyConfig = {
  clientId: string;
  clientSecret: string;
};

/**
 * Server-wide security toggles. All default ON; operators opt OUT
 * explicitly via env. We surface them here so call sites can read
 * `loadSecurityConfig().redact` instead of repeating the `!== 'false'`
 * comparison and so misspelled env values (`"FALSE"`, `"0"`) don't
 * silently disable a control.
 */
export type SecurityConfig = {
  redact: boolean;
  audit: boolean;
  rateLimit: boolean;
  /**
   * Opt-IN toggle for identity tools (`getIdentityByItem`, `getIdentity`).
   * Default `false` — opposite posture from `redact` / `audit` / `rateLimit`
   * because identity is the highest-PII surface in the Pluggy API (CPF,
   * full name, addresses, phones, emails, salary, related parties). The
   * operator must explicitly set `PLUGGY_MCP_ENABLE_IDENTITY=true` to
   * unlock the tools; until they do, the registered tools refuse to call
   * the SDK and return a `FORBIDDEN` envelope.
   */
  enableIdentity: boolean;
};

/**
 * Per-tool rate-limit budgets. Sourced from env so an operator can tune
 * them without rebuilding; defaults are conservative because the server
 * fronts a paid upstream API. Invalid or missing values fall back to the
 * defaults — we never throw at config load.
 */
export type RateLimitConfig = {
  perMinute: number;
  perDay: number;
};

const DEFAULT_RATE_LIMIT_PER_MINUTE = 30;
const DEFAULT_RATE_LIMIT_PER_DAY = 200;

/**
 * Cached config — `loadPluggyConfig` is called from both `main()` (for the
 * startup warning) and `getPluggyClient` (on first tool use). Reading env
 * twice is harmless, but memoizing keeps the call sites cheap and makes
 * the intent obvious: env is read once per process.
 */
let cached: PluggyConfig | null = null;
let cachedSecurity: SecurityConfig | null = null;
let cachedRateLimit: RateLimitConfig | null = null;
/**
 * Cached items allowlist. We store `null` to mean "no restriction" and
 * an empty `Set` would mean "allow nothing" — these are semantically
 * different. A second sentinel boolean tracks whether we have loaded yet.
 */
let cachedItemsAllowlist: Set<string> | null = null;
let itemsAllowlistLoaded = false;

/**
 * Load Pluggy credentials. Returns `null` when either credential is missing
 * so callers can render a friendly error to the LLM instead of crashing.
 * The result is memoized for the lifetime of the process.
 */
export function loadPluggyConfig(): PluggyConfig | null {
  if (cached) {
    return cached;
  }

  const clientId = process.env.PLUGGY_CLIENT_ID;
  const clientSecret = process.env.PLUGGY_CLIENT_SECRET;

  // After capturing into memory, scrub the originals so future tools or
  // dependencies cannot read them out of process.env. The memoized
  // `cached` value above is the only place the secret lives from now on.
  // Note: a child process spawned BEFORE this point would still have
  // inherited the env, so this should run as early as possible during
  // startup (it runs on first call, which `main()` triggers up-front).
  // We scrub even when one credential is missing so a partially-set env
  // doesn't leak the half that was present.
  delete process.env.PLUGGY_CLIENT_ID;
  delete process.env.PLUGGY_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return null;
  }

  cached = { clientId, clientSecret };
  return cached;
}

/**
 * Read security toggles from the environment. All default ON; the only
 * way to disable a control is to explicitly set its env var to the
 * literal string `"false"` (case-sensitive — see comment on `SecurityConfig`).
 *
 * Memoized for the same reason as the credentials: env is read once per
 * process. We do NOT delete the toggle envs after reading — they are not
 * secrets, and downstream child processes (if any) seeing the same value
 * is the correct behavior.
 */
export function loadSecurityConfig(): SecurityConfig {
  if (cachedSecurity) return cachedSecurity;
  cachedSecurity = {
    redact: process.env.PLUGGY_MCP_REDACT !== 'false',
    audit: process.env.PLUGGY_MCP_AUDIT !== 'false',
    rateLimit: process.env.PLUGGY_MCP_RATELIMIT !== 'false',
    // Opt-IN: only the literal string "true" enables identity tools.
    // Any other value (unset, "1", "yes", "TRUE", typos) is treated as
    // disabled — fail-closed because the data unlocked here is the
    // highest-PII surface in the API.
    enableIdentity: process.env.PLUGGY_MCP_ENABLE_IDENTITY === 'true',
  };
  return cachedSecurity;
}

/**
 * Read per-tool rate-limit budgets from `PLUGGY_MCP_RATELIMIT_PER_MIN`
 * and `PLUGGY_MCP_RATELIMIT_PER_DAY`. Values are parsed as base-10
 * integers; anything non-positive or non-numeric falls back to the
 * defaults silently. We deliberately do NOT throw — a typo in env must
 * not crash the stdio transport at startup.
 *
 * Memoized for the same reason as `loadSecurityConfig`: env is a
 * once-per-process input. Sourcing the budgets here (rather than from
 * a per-call `opts` arg) ensures every tool sees the same operator
 * intent — there is no path for a caller to silently widen the limit.
 */
export function loadRateLimitConfig(): RateLimitConfig {
  if (cachedRateLimit) return cachedRateLimit;
  cachedRateLimit = {
    perMinute: parsePositiveInt(
      'PLUGGY_MCP_RATELIMIT_PER_MIN',
      process.env.PLUGGY_MCP_RATELIMIT_PER_MIN,
      DEFAULT_RATE_LIMIT_PER_MINUTE,
    ),
    perDay: parsePositiveInt(
      'PLUGGY_MCP_RATELIMIT_PER_DAY',
      process.env.PLUGGY_MCP_RATELIMIT_PER_DAY,
      DEFAULT_RATE_LIMIT_PER_DAY,
    ),
  };
  return cachedRateLimit;
}

/**
 * Read the optional `PLUGGY_ITEM_IDS` env var: a comma-separated list of
 * Pluggy Item UUIDs that the operator wants to scope this MCP server to.
 *
 * Returns:
 *   - `null` when the env var is ABSENT (`undefined`). This signals
 *     "no restriction" to the tools — they fall back to their default
 *     behavior of accepting any itemId.
 *   - an EMPTY `Set<string>` when the env var is PRESENT but contains
 *     only whitespace/commas after trimming. This is a deliberate
 *     "deny all" — fail-closed posture; the operator probably typed the
 *     var name without filling in ids, and we'd rather refuse every
 *     gated call than silently widen access.
 *   - a non-empty `Set<string>` of trimmed, lower-cased UUIDs otherwise.
 *     Tools that take a raw `itemId` parameter compare against this set
 *     (also lower-cased) and refuse to call the SDK for ids not in it.
 *
 * We intentionally do NOT validate UUID shape here: an operator who
 * mistypes an id should see the tool fail with `ITEM_NOT_ALLOWED`
 * (because the typo will never match a real id) rather than crash the
 * stdio transport at startup. The result is memoized for the lifetime
 * of the process — env is a once-per-process input, same as other
 * loaders in this file.
 */
export function loadItemsAllowlist(): Set<string> | null {
  if (itemsAllowlistLoaded) return cachedItemsAllowlist;
  itemsAllowlistLoaded = true;

  const raw = process.env.PLUGGY_ITEM_IDS;
  if (raw === undefined) {
    // Absent — no restriction.
    cachedItemsAllowlist = null;
    return null;
  }

  const ids = raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);

  // Present-but-empty (whitespace/commas only) is treated as DENY ALL.
  // Fail-closed: the operator opted into scoping but provided no ids,
  // which is almost certainly a misconfiguration we should surface
  // loudly rather than silently widen access.
  cachedItemsAllowlist = new Set(ids);
  return cachedItemsAllowlist;
}

/**
 * Test whether a caller-supplied `itemId` is permitted by the operator's
 * allowlist. Returns `true` when no allowlist is configured (`null`);
 * returns `false` for every id when the allowlist is the empty set
 * ("deny all" — `PLUGGY_ITEM_IDS` set but empty).
 *
 * The comparison is case-insensitive — Pluggy ids are UUIDs, and we don't
 * want a request that differs only in case from a known id to be denied
 * (or, worse, accepted only sometimes depending on which case the
 * operator typed into env).
 */
export function isItemAllowed(itemId: string): boolean {
  const allowlist = loadItemsAllowlist();
  if (allowlist === null) return true;
  if (allowlist.size === 0) return false;
  return allowlist.has(itemId.trim().toLowerCase());
}

function parsePositiveInt(
  name: string,
  raw: string | undefined,
  fallback: number,
): number {
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) {
    // Operator typo or non-positive value — log so the silent fallback
    // is at least discoverable. We deliberately do NOT log on the
    // unset/empty path (that's the documented "use default" route).
    logEvent('config_invalid', { var: name, fallback });
    return fallback;
  }
  return n;
}

/**
 * Emit a single-line summary of the resolved security toggles, plus a
 * loud warning when redaction is disabled. Called once from `main()`.
 *
 * Kept separate from `loadSecurityConfig()` because the loader is also
 * called from inside tool handlers and we only want the summary once at
 * startup — not on every tool call.
 */
export function logSecurityConfig(): void {
  const cfg = loadSecurityConfig();
  const allowlist = loadItemsAllowlist();
  logEvent('security_config', {
    redact: cfg.redact,
    audit: cfg.audit,
    rateLimit: cfg.rateLimit,
    enableIdentity: cfg.enableIdentity,
    // Surface only the *count* of allowed items — the actual UUIDs are
    // operator-controlled identifiers and shouldn't show up unbidden in
    // logs. `null` documents "no restriction" explicitly.
    itemsAllowlistCount: allowlist === null ? null : allowlist.size,
  });
  if (!cfg.redact) {
    console.error(
      '[pluggy-mcp] WARN: PII redaction DISABLED — raw CPF/account numbers will reach the LLM context. ' +
        'Set PLUGGY_MCP_REDACT=true to enable.',
    );
  }
  if (!cfg.audit) {
    // Sensitive-event audit lines are still emitted unconditionally (see
    // `audit()` in src/security/audit.ts) — this WARN flags only the
    // suppression of routine, non-sensitive audit traffic.
    console.error(
      '[pluggy-mcp] WARN: audit logging DISABLED — non-sensitive tool calls will not be recorded. ' +
        'Set PLUGGY_MCP_AUDIT=true to enable. (Sensitive-event audit is unbypassable.)',
    );
  }
  if (cfg.enableIdentity) {
    // Identity tools are opt-IN because they unlock CPF, full name,
    // addresses, phones, emails, salary, patrimony, and related-party
    // data. Emit a startup WARN so an operator who set the var
    // accidentally sees it surfaced loudly. Sensitive-event audit lines
    // fire on every call regardless of the audit toggle.
    console.error(
      '[pluggy-mcp] WARN: PLUGGY_MCP_ENABLE_IDENTITY=true — getIdentityByItem/getIdentity will return CPF, full name, addresses, phones, emails, salary, and related-party data. Every call is audit-logged with sensitive=true.',
    );
  }
  if (allowlist !== null && allowlist.size === 0) {
    // PLUGGY_ITEM_IDS is set but empty — every gated tool will refuse
    // every itemId. Surface this so an operator who mistyped catches it
    // at startup instead of after a chain of FORBIDDEN envelopes.
    logEvent('items_allowlist_empty', {
      message: 'PLUGGY_ITEM_IDS is set but empty; all gated tools will deny every itemId.',
    });
  }
}

/**
 * Process-wide server metadata (kept in one place so server.json and the
 * MCP server initialization stay in sync).
 */
export const SERVER_INFO = {
  name: 'pluggy-mcp',
  title: 'Pluggy MCP',
  version: '1.0.0',
} as const;
