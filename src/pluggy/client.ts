/**
 * Thin wrapper around the official `pluggy-sdk` PluggyClient.
 *
 * Centralizing construction here means:
 *  - tool handlers don't each repeat credential plumbing,
 *  - we get one place to swap in mocks or fakes for tests later,
 *  - lazy instantiation: the MCP server can start (and list its tools)
 *    even when credentials are absent. The client is only built the
 *    first time a tool actually needs to call Pluggy.
 */

import { PluggyClient } from 'pluggy-sdk';
import { loadPluggyConfig } from '../config.js';

/**
 * Shape of the `GET /accounts/{id}/balance` endpoint response, mirroring
 * the documented Pluggy Real-Time Balance schema. Documented here (not in
 * `src/tools/accounts.ts`) because the SDK does not surface this endpoint
 * and we need a typed return for the subclass below.
 */
export interface RealTimeBalance {
  balance: number;
  blockedBalance: number | null;
  automaticallyInvestedBalance: number | null;
  currencyCode: string;
  updateDateTime: string;
}

/**
 * Subclass of `PluggyClient` widening two `protected` members from the SDK
 * so we can use them outside of the class hierarchy:
 *   - `createGetRequest` → wrapped as `fetchAccountBalance`, the one
 *     read-only endpoint the SDK is missing for PR3 (real-time balance).
 *   - `getApiKey` → wrapped as `fetchApiKey` so the PR4 "premium"
 *     endpoints in `./rawFetch.ts` can reuse the SAME cached JWT this
 *     client maintains (no second auth handshake, no second token cache).
 *
 * We deliberately keep this widening minimal — `serviceInstance`,
 * `baseUrl`, `defaultHeaders` stay protected so call sites cannot
 * accidentally bypass the SDK's configured behavior (e.g. a `PLUGGY_API_URL`
 * override on the SDK base).
 *
 * Using `createGetRequest` for the balance endpoint matters because it
 * already handles auth (X-API-KEY refresh), base URL resolution, JSON-
 * with-Dates parsing, and error normalization so our error classifier
 * still works.
 */
class PluggyClientExtended extends PluggyClient {
  /**
   * Fetch the real-time balance for an account. Documented Pluggy endpoint
   * but not exposed by the 0.85.x SDK; we go through the SDK's
   * `createGetRequest` so auth and error handling stay consistent with
   * every other tool.
   */
  fetchAccountBalance(accountId: string): Promise<RealTimeBalance> {
    return this.createGetRequest<RealTimeBalance>(`accounts/${accountId}/balance`);
  }

  /**
   * Expose the SDK's protected `getApiKey()` so `rawFetch.ts` can share
   * the same JWT cache. Returns a cached token and refreshes when within
   * 30s of expiry — safe to call on every request.
   */
  fetchApiKey(): Promise<string> {
    return this.getApiKey();
  }
}

let cached: PluggyClientExtended | null = null;

/**
 * Returned when credentials are missing. Tool handlers translate this
 * into a user-facing message; we deliberately do not throw so the model
 * sees a clean error instead of a raw stack trace.
 */
export class MissingCredentialsError extends Error {
  constructor() {
    super(
      'PLUGGY_CLIENT_ID and PLUGGY_CLIENT_SECRET environment variables are required.',
    );
    this.name = 'MissingCredentialsError';
  }
}

/**
 * Get (or lazily build) the PluggyClient singleton.
 *
 * Throws `MissingCredentialsError` if env vars are not set so callers can
 * differentiate a configuration problem from an upstream failure.
 */
export function getPluggyClient(): PluggyClientExtended {
  if (cached) {
    return cached;
  }

  const config = loadPluggyConfig();
  if (!config) {
    throw new MissingCredentialsError();
  }

  cached = new PluggyClientExtended({
    clientId: config.clientId,
    clientSecret: config.clientSecret,
  });
  return cached;
}
