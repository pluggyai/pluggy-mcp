/**
 * `getRecurringPayments` / `getInsightsBook` tools.
 *
 * These two endpoints are premium Pluggy features served from sibling
 * hosts the SDK does not surface:
 *   - `https://enrichment-api.pluggy.ai/recurring-payments`
 *       Detects subscription-like patterns in an Item's transactions
 *       (Netflix, Spotify, etc.).
 *   - `https://insights-api.pluggy.ai/book?itemIds=...`
 *       Aggregates account-level KPIs across one or more Items.
 *
 * Both go through `pluggyRawFetch` (`../pluggy/rawFetch.ts`), which
 * reuses the SDK's apiKey cache so we don't redo the auth handshake.
 *
 * IMPORTANT: these are PREMIUM endpoints. Pluggy returns 403 for
 * accounts whose plan does not include enrichment / insights. The tool
 * descriptions tell the LLM that a 403 means "feature not enabled" —
 * not a transient failure — so it should not auto-retry.
 *
 * Allowlist scope:
 *   - `getRecurringPayments` takes one `itemId` → pre-fetch check.
 *   - `getInsightsBook` takes `itemIds: string[]` → validates EACH id
 *     against the allowlist. ANY denial returns a single hardcoded
 *     FORBIDDEN envelope; no upstream call is made.
 *
 * The recurring-payments response shape is institution-derived (vendor
 * names, descriptions) → wrap free text in `<untrusted>`. The insights
 * book response is documented as KPI numerics → still wrap any free
 * text we surface.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { performance } from 'node:perf_hooks';
import { z } from 'zod';
import { pluggyRawFetch } from '../pluggy/rawFetch.js';
import { ErrorCodeEnum } from '../util/errors.js';
import { ensureOutputShape } from '../util/outputShape.js';
import {
  buildErrorResponse,
  buildLiteralErrorResponse,
  buildSuccessResponse,
} from '../util/toolResponse.js';
import { loadSecurityConfig, isItemAllowed } from '../config.js';
import {
  audit,
  checkRateLimit,
  hashArgsSafely,
  wrapUntrusted,
  UNTRUSTED_PREAMBLE,
  LOCAL_RATE_LIMITED_MESSAGE,
  ITEM_NOT_ALLOWED_MESSAGE,
} from '../security/index.js';

const ENRICHMENT_RECURRING_URL =
  'https://enrichment-api.pluggy.ai/recurring-payments';
const INSIGHTS_BOOK_URL = 'https://insights-api.pluggy.ai/book';

// Hardcoded — `getInsightsBook` accepts an array of itemIds and we want
// a single, server-controlled string when ANY of them is denied. Avoids
// naming the offending id in the LLM channel (consistent with
// `ITEM_NOT_ALLOWED_MESSAGE` posture).
const INSIGHTS_ITEM_NOT_ALLOWED_MESSAGE =
  'One or more itemIds not in PLUGGY_ITEM_IDS allowlist.';

// Defense-in-depth: zod `.min(1)` already rejects empty arrays at the
// SDK validation layer. Should that ever change (e.g. someone loosens
// the schema), an empty `itemIds=` query string would let Pluggy
// interpret the call as "return all" — silently widening scope. We
// fail closed with a hardcoded message instead.
const INSIGHTS_NO_ITEM_IDS_MESSAGE =
  'getInsightsBook requires at least one itemId.';

// ---------------------------------------------------------------------------
// `getRecurringPayments`
// ---------------------------------------------------------------------------
//
// The enrichment response shape is not documented at type-level by
// Pluggy; we accept `unknown` and surface it as a pass-through `result`
// field validated by `z.unknown()`. Free-text strings inside the payload
// stay wrapped server-side via the response normalizer below.

// Single source of truth — see `transactions.ts` for rationale.
const GetRecurringPaymentsOutputSchema = z.object({
  ok: z.boolean(),
  itemId: z.string().optional(),
  // Pass-through payload; the upstream shape is opaque to this server.
  // We pre-normalize free-text via `normalizeUnknownPayload` before
  // emitting so an institution-composed string can't bypass the
  // <untrusted> wrap.
  result: z.unknown().optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

/**
 * Hardcoded recursion ceiling for the two response normalizers below.
 * The upstream enrichment / insights payloads are loosely typed and could
 * — accidentally or maliciously — contain deeply nested structures that
 * would blow the stack. 10 levels is comfortably deeper than any
 * documented Pluggy response we've seen; past that we truncate the
 * subtree to a wrapped sentinel string so the LLM still sees a value
 * but the recursion terminates safely.
 */
const MAX_NORMALIZE_DEPTH = 10;
const MAX_DEPTH_SENTINEL = '[truncated: max depth]';

/**
 * Walk a loosely-typed enrichment/insights response and wrap every string
 * leaf in `<untrusted>`. The upstream shapes are documented loosely and
 * may change; a recursive wrap is the safest posture short of pinning a
 * strict schema. We deliberately do NOT mutate the input.
 *
 * NUMBERS / BOOLEANS / NULLS pass through unchanged — KPI values are the
 * point of the tool. Object keys are NOT wrapped (they are server-
 * controlled by Pluggy, not adversarial).
 *
 * Shared by `getRecurringPayments` and `getInsightsBook`: both surfaces
 * have identical normalization needs today. If Pluggy publishes a tighter
 * schema for one of them, fork into a dedicated normalizer at that point.
 */
function normalizeUnknownPayload(value: unknown, depth: number = 0): unknown {
  if (depth >= MAX_NORMALIZE_DEPTH) return wrapUntrusted(MAX_DEPTH_SENTINEL);
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return wrapUntrusted(value);
  if (Array.isArray(value)) {
    return value.map((v) => normalizeUnknownPayload(v, depth + 1));
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    // `Object.create(null)` so the resulting object has no prototype —
    // serializing through JSON later cannot collide with `Object.prototype`
    // accessors, and explicit skip-listing the three dangerous keys below
    // gives belt-and-braces against an upstream payload trying to inject
    // a `__proto__` / `constructor` / `prototype` field.
    const out: Record<string, unknown> = Object.create(null);
    for (const [k, v] of Object.entries(obj)) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      out[k] = normalizeUnknownPayload(v, depth + 1);
    }
    return out;
  }
  // numbers, booleans, bigints — pass through.
  return value;
}

export function registerGetRecurringPaymentsTool(server: McpServer): void {
  const toolName = 'getRecurringPayments';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'Detect recurring (subscription-like) payments across the ' +
        'transactions of a Pluggy Item. Premium Pluggy feature — your ' +
        'account may return 403 if your plan does not include ' +
        'enrichment/insights. All free-text fields in the response are ' +
        'wrapped in <untrusted>. ' +
        'When the server is configured with PLUGGY_ITEM_IDS, only itemIds ' +
        'in the allowlist will be fetched; others return FORBIDDEN.',
      inputSchema: {
        itemId: z
          .string()
          .uuid()
          .describe('The Pluggy Item id (UUID) to analyze.'),
      },
      outputSchema: GetRecurringPaymentsOutputSchema.shape,
      annotations: {
        title: 'Get Recurring Payments (premium)',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ itemId }) => {
      const start = performance.now();
      let outcome: 'success' | 'error' = 'success';
      let errorCode: string | undefined;
      let requestId: string | undefined;
      let rateLimitReason: 'PER_MINUTE' | 'PER_DAY' | undefined;
      // Subscription/vendor data is financial-behavior PII — flip sensitive
      // ONLY when we actually hit the upstream. Gate denials stay false.
      let sensitive = false;
      try {
        const sec = loadSecurityConfig();
        const rl = sec.rateLimit
          ? checkRateLimit(toolName)
          : { allowed: true as const };
        if (!rl.allowed) {
          outcome = 'error';
          errorCode = 'LOCAL_RATE_LIMITED';
          rateLimitReason = rl.reason;
          return buildLiteralErrorResponse('LOCAL_RATE_LIMITED', LOCAL_RATE_LIMITED_MESSAGE);
        }

        if (!isItemAllowed(itemId)) {
          outcome = 'error';
          errorCode = 'FORBIDDEN';
          return buildLiteralErrorResponse('FORBIDDEN', ITEM_NOT_ALLOWED_MESSAGE);
        }

        sensitive = true;
        const raw = await pluggyRawFetch(
          ENRICHMENT_RECURRING_URL,
          'POST',
          { itemId },
        );
        const result = normalizeUnknownPayload(raw);

        const output = { ok: true as const, itemId, result };
        ensureOutputShape(GetRecurringPaymentsOutputSchema, output, {
          tool: toolName,
        });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'enrichmentRecurringPayments' },
          GetRecurringPaymentsOutputSchema,
        );
        errorCode = r.errorCode;
        requestId = r.requestId;
        return r.result;
      } finally {
        audit({
          tool: toolName,
          outcome,
          errorCode,
          durationMs: Math.round(performance.now() - start),
          ...hashArgsSafely({ itemId }, ['itemId']),
          sensitive,
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}

// ---------------------------------------------------------------------------
// `getInsightsBook`
// ---------------------------------------------------------------------------

// Single source of truth — see `transactions.ts` for rationale.
const GetInsightsBookOutputSchema = z.object({
  ok: z.boolean(),
  itemIds: z.array(z.string()).optional(),
  // Pass-through; same posture as `getRecurringPayments.result`.
  result: z.unknown().optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

/**
 * Hardcoded ceiling on the number of itemIds accepted per call. The
 * insights endpoint will happily accept large batches, but each id
 * appears in the URL query string and a runaway agent could hit our
 * per-tool rate limit with one giant call. Pluggy's docs don't pin a
 * hard limit; 25 is comfortably above any realistic LLM-driven workflow
 * (one user's portfolio rarely spans more than a handful of institutions)
 * and small enough that the resulting URL stays well under any sensible
 * proxy's URI length cap.
 */
const MAX_INSIGHTS_ITEM_IDS = 25;

export function registerGetInsightsBookTool(server: McpServer): void {
  const toolName = 'getInsightsBook';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'Fetch the insights "book" — aggregated KPIs (cash flow, recurring ' +
        'income / expenses, account-level summaries) across one or more ' +
        'Pluggy Items. Premium Pluggy feature — your account may return ' +
        '403 if your plan does not include enrichment/insights. All ' +
        'free-text fields in the response are wrapped in <untrusted>. ' +
        'When PLUGGY_ITEM_IDS is configured, every supplied itemId is ' +
        'validated against the allowlist; ANY denial returns FORBIDDEN ' +
        'without calling the SDK.',
      inputSchema: {
        itemIds: z
          .array(z.string().uuid())
          .min(1)
          .max(MAX_INSIGHTS_ITEM_IDS)
          .describe(
            `One or more Pluggy Item ids (UUIDs). Max ${MAX_INSIGHTS_ITEM_IDS}.`,
          ),
      },
      outputSchema: GetInsightsBookOutputSchema.shape,
      annotations: {
        title: 'Get Insights Book (premium)',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async (args) => {
      const { itemIds } = args;
      const start = performance.now();
      let outcome: 'success' | 'error' = 'success';
      let errorCode: string | undefined;
      let requestId: string | undefined;
      let rateLimitReason: 'PER_MINUTE' | 'PER_DAY' | undefined;
      // Income / cash-flow aggregates are financial-behavior PII — flip
      // sensitive ONLY when we actually hit the upstream.
      let sensitive = false;
      try {
        const sec = loadSecurityConfig();
        const rl = sec.rateLimit
          ? checkRateLimit(toolName)
          : { allowed: true as const };
        if (!rl.allowed) {
          outcome = 'error';
          errorCode = 'LOCAL_RATE_LIMITED';
          rateLimitReason = rl.reason;
          return buildLiteralErrorResponse('LOCAL_RATE_LIMITED', LOCAL_RATE_LIMITED_MESSAGE);
        }

        // Defense-in-depth runtime check — zod `.min(1)` should already
        // have rejected an empty array, but a future schema loosening
        // would otherwise silently widen the upstream call to "all items".
        if (itemIds.length === 0) {
          outcome = 'error';
          errorCode = 'UNKNOWN';
          return buildLiteralErrorResponse('UNKNOWN', INSIGHTS_NO_ITEM_IDS_MESSAGE);
        }

        // Validate EVERY id against the allowlist. The response envelope
        // carries a uniform FORBIDDEN message regardless of which id was
        // denied, so the LLM cannot infer which id was the bad one from
        // the envelope. (The allowlist is `null` when unset — `every`
        // returns true and we fall through.)
        const allAllowed = itemIds.every((id) => isItemAllowed(id));
        if (!allAllowed) {
          outcome = 'error';
          errorCode = 'FORBIDDEN';
          return buildLiteralErrorResponse('FORBIDDEN', INSIGHTS_ITEM_NOT_ALLOWED_MESSAGE);
        }

        // Pluggy's insights book takes itemIds as a repeated `itemIds`
        // query parameter. URLSearchParams handles encoding for us.
        const params = new URLSearchParams();
        for (const id of itemIds) {
          params.append('itemIds', id);
        }
        const url = `${INSIGHTS_BOOK_URL}?${params.toString()}`;

        sensitive = true;
        const raw = await pluggyRawFetch(url, 'POST');
        const result = normalizeUnknownPayload(raw);

        const output = { ok: true as const, itemIds, result };
        ensureOutputShape(GetInsightsBookOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'insightsBook' },
          GetInsightsBookOutputSchema,
        );
        errorCode = r.errorCode;
        requestId = r.requestId;
        return r.result;
      } finally {
        audit({
          tool: toolName,
          outcome,
          errorCode,
          durationMs: Math.round(performance.now() - start),
          // Hashes both the full args object (`argsHash`) and the
          // `itemIds` array as one field — `hashArgsSafely` handles
          // arrays by hashing the array as a single value, so the
          // resulting `itemIdsHash` correlates calls with the same
          // ordered list of itemIds.
          ...hashArgsSafely(args, ['itemIds']),
          sensitive,
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}
