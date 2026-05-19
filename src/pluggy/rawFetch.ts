/**
 * Raw HTTP wrapper for Pluggy "premium" endpoints the SDK does not surface.
 *
 * The SDK's `PluggyClient` covers the documented `api.pluggy.ai` surface
 * area, but two upcoming PR4 tools target sibling hosts that the SDK does
 * not know about:
 *   - `enrichment-api.pluggy.ai/recurring-payments` (subscription detection)
 *   - `insights-api.pluggy.ai/book` (account KPIs)
 *
 * Both hosts authenticate with the same `X-API-KEY` short-lived token the
 * SDK already manages internally. Rather than redo the auth handshake by
 * hand, we reuse the SHARED `PluggyClientExtended` singleton from
 * `./client.ts` — its `fetchApiKey()` returns the SDK's cached JWT (the
 * same one balance / accounts / transactions use), so there's exactly one
 * token cache and one refresh schedule across every Pluggy code path here.
 *
 * Note: these endpoints are PREMIUM. Pluggy returns 403 for accounts
 * whose plan does not include enrichment / insights. We do NOT auto-retry
 * 403 — the tool descriptions warn the LLM that a 403 means the upstream
 * feature is not unlocked, not a transient failure.
 */

import { getPluggyClient } from './client.js';
import { logEvent } from '../util/log.js';

/**
 * Minimal shape we throw on non-2xx responses. Mirrors the fields that
 * `../util/errors.ts:extractStatus` probes (`response.statusCode`,
 * `statusCode`) so the existing classifier maps a raw fetch failure to
 * the same `errorCode` an SDK call would have produced.
 *
 * We deliberately do NOT carry the response body at all — upstream JSON
 * on a 4xx may contain partial PII or echo back request fields, and
 * keeping it on the error object risks accidental serialization (e.g.
 * `JSON.stringify(err)`, debugger inspection, or a future logger that
 * spreads error properties). The hardcoded message is server-controlled
 * and safe to surface.
 */
export class PluggyRawFetchError extends Error {
  readonly statusCode: number;
  readonly response: { statusCode: number };
  constructor(statusCode: number) {
    super(`Pluggy raw fetch failed with HTTP ${statusCode}`);
    this.name = 'PluggyRawFetchError';
    this.statusCode = statusCode;
    // Duplicate the status under `response` so `extractStatus()` finds it
    // through any of its probe paths. Cheap and keeps the existing error
    // classifier oblivious to the source (SDK vs raw fetch).
    this.response = { statusCode };
  }
}

export type PluggyRawFetchMethod = 'GET' | 'POST';

/**
 * Fetch a Pluggy "premium" endpoint that the SDK does not surface.
 *
 * - Pulls a fresh `X-API-KEY` via the shared SDK client (so the token
 *   cache and refresh policy stay consistent across tools).
 * - Sends `Content-Type: application/json` when a body is provided.
 * - Parses the response as JSON; non-2xx responses throw a
 *   `PluggyRawFetchError` shaped so `classifyAndReport` maps it to the
 *   same `errorCode` as an SDK call would (`UNAUTHORIZED`, `FORBIDDEN`,
 *   `NOT_FOUND`, `RATE_LIMITED`, `UPSTREAM_5XX`).
 *
 * Uses the platform `fetch` (Node 18+). The SDK uses `got` internally;
 * we deliberately do NOT depend on `got` here to keep this module's
 * surface area small and avoid a second HTTP stack worth of configuration.
 */
export async function pluggyRawFetch(
  url: string,
  method: PluggyRawFetchMethod,
  body?: unknown,
): Promise<unknown> {
  // Reuse the shared `PluggyClientExtended` singleton — same JWT cache as
  // every SDK-backed tool. Throws `MissingCredentialsError` if env is
  // unset, which `classifyAndReport` maps to `MISSING_CREDENTIALS`.
  const apiKey = await getPluggyClient().fetchApiKey();
  const headers: Record<string, string> = {
    'X-API-KEY': apiKey,
    // Pluggy returns JSON; ask for it explicitly so any future content
    // negotiation default doesn't bite us.
    Accept: 'application/json',
  };
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const res = await fetch(url, init);

  // Read body once. On the 2xx path, non-JSON is treated as a hard
  // failure — these endpoints are documented as JSON and a text body in
  // a "success" response usually indicates an upstream proxy or auth
  // interstitial we should NOT surface as data. On the error path we
  // also drop the body: the upstream JSON may contain partial PII or
  // echo back request fields, and the classifier only needs the status.
  let parsed: unknown = undefined;
  let jsonOk = true;
  const text = await res.text();
  if (text.length > 0) {
    try {
      parsed = JSON.parse(text);
    } catch {
      jsonOk = false;
    }
  }

  if (!res.ok) {
    throw new PluggyRawFetchError(res.status);
  }
  if (!jsonOk) {
    // Log the endpoint host + path (no query string) instead of the full
    // URL — insights book carries itemIds in the query and we never want
    // raw ids on stderr. URL parsing is best-effort; on failure we emit
    // a server-controlled sentinel rather than the raw input.
    let endpoint = 'unknown';
    try {
      const u = new URL(url);
      endpoint = `${u.host}${u.pathname}`;
    } catch {
      endpoint = 'unparseable';
    }
    logEvent('raw_fetch_non_json_body', {
      endpoint,
      status: res.status,
      len: text.length,
    });
    throw new PluggyRawFetchError(res.status);
  }
  return parsed;
}
