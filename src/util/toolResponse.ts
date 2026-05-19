/**
 * Shared MCP response builders for tool handlers.
 *
 * Every tool in this server shares two near-identical catch/return shapes:
 *
 *   1. The `try { … } catch (err)` block: classify the upstream error,
 *      validate the envelope against the tool's outputSchema, and return
 *      a structured MCP result with `isError: true`.
 *   2. The pre-flight rejections (LOCAL_RATE_LIMITED, ITEM_NOT_ALLOWED):
 *      return a hardcoded envelope without calling the upstream SDK.
 *
 * These helpers consolidate both patterns. They live in `util/` rather
 * than `security/` because they are pure response shaping — no auditing,
 * no rate-limit state, no redaction.
 *
 * Why a standalone helper, NOT a `withSecurity`/`withAudit` wrapper: a
 * wrapper would have to mutate handler-local closure variables
 * (`outcome`, `errorCode`, `requestId`, `rateLimitReason`) to keep the
 * `finally` audit line correct. That coupling makes the wrapper fragile
 * to refactor — explicit return values keep the data flow visible at
 * each call site.
 */

import type { ZodTypeAny } from 'zod';
import { classifyAndReport } from './errors.js';
import { ensureErrorEnvelope } from './outputShape.js';

/**
 * Shape of an MCP tool response carrying a structured error envelope.
 * The MCP SDK's `registerTool` callback signature requires an index
 * signature on the returned object (it allows arbitrary additional
 * fields), so we mirror that here — without it TS rejects the helper's
 * return type at the call site.
 */
interface ToolErrorResponse {
  [x: string]: unknown;
  isError: true;
  structuredContent: {
    ok: false;
    errorCode: string;
    message: string;
    requestId?: string;
  };
  content: [{ type: 'text'; text: string }];
}

/**
 * Classify an error, validate the envelope against the tool's
 * outputSchema, and build the MCP error response.
 *
 * Returns the response alongside `errorCode` and `requestId` so the
 * caller's `finally` block can populate the audit line. We return these
 * explicitly rather than mutating closure variables — see file header.
 */
export function buildErrorResponse<T extends ZodTypeAny>(
  err: unknown,
  ctx: { tool: string; operation?: string },
  schema: T,
): { result: ToolErrorResponse; errorCode: string; requestId: string } {
  const safe = classifyAndReport(err, ctx);
  const envelope = ensureErrorEnvelope(
    schema,
    {
      ok: false as const,
      errorCode: safe.errorCode,
      requestId: safe.requestId,
      message: safe.message,
    },
    { tool: ctx.tool },
  );
  return {
    result: {
      isError: true,
      structuredContent: envelope,
      content: [{ type: 'text', text: safe.message }],
    },
    errorCode: safe.errorCode,
    requestId: safe.requestId,
  };
}

/**
 * Build an MCP error response for a pre-flight rejection that does NOT
 * involve an upstream Pluggy call (e.g. LOCAL_RATE_LIMITED,
 * ITEM_NOT_ALLOWED). The envelope is a hardcoded literal — no
 * outputSchema validation needed because the shape is built from
 * compile-time constants that every tool's outputSchema already accepts.
 */
export function buildLiteralErrorResponse(
  errorCode: string,
  message: string,
): ToolErrorResponse {
  return {
    isError: true,
    structuredContent: { ok: false, errorCode, message },
    content: [{ type: 'text', text: message }],
  };
}

/**
 * Shape of an MCP tool response carrying a structured success envelope
 * mirrored as JSON in the `content` text channel.
 *
 * The MCP SDK's `registerTool` callback signature allows additional
 * fields on the returned object, so we mirror the same index signature
 * used by `ToolErrorResponse`.
 */
interface ToolSuccessResponse<T extends { ok: true }> {
  [x: string]: unknown;
  structuredContent: T;
  content: [{ type: 'text'; text: string }];
}

/**
 * Build an MCP tool success response that mirrors `structuredContent`
 * as a serialized-JSON `TextContent` block.
 *
 * Why: per the MCP spec (2025-06-18, "Structured Content"):
 *   "For backwards compatibility, a tool that returns structured content
 *    SHOULD also return the serialized JSON in a TextContent block."
 *
 * Many clients (notably claude.ai today) only surface `content[].text`
 * to the model and ignore `structuredContent` entirely. Without the
 * mirror, a multi-step workflow such as `getAccounts` →
 * `listTransactions` is broken: the `accountId` lives in
 * `structuredContent.accounts[].id` but never reaches the model, so the
 * follow-up call cannot be constructed.
 *
 * Mirroring the validated `output` exactly keeps the invariant
 * "text === JSON.stringify(structuredContent)" trivially true and
 * impossible to drift. Existing `<untrusted>` markers wrapping
 * institution-composed strings ride along inside the JSON values, so
 * indirect prompt-injection posture is unchanged — the wire protocol
 * was already sending `structuredContent` through the same transport,
 * the LLM just couldn't see it.
 */
export function buildSuccessResponse<T extends { ok: true }>(
  structured: T,
): ToolSuccessResponse<T> {
  // Runtime guard — the `T extends { ok: true }` constraint only fires at
  // compile time; a caller could bypass it via `as any` (or via a refactor
  // that loses the literal type) and end up returning a failure payload
  // through the success channel WITHOUT `isError: true`. Banking MCP:
  // belt-and-suspenders, fail loudly so the bug surfaces in tests instead
  // of silently presenting an error payload as success to the LLM.
  if ((structured as { ok: unknown }).ok !== true) {
    throw new Error('buildSuccessResponse called with non-success envelope');
  }

  // JSON.stringify can throw on BigInt values, circular references, or a
  // `toJSON` that itself throws. None of those shapes are reachable in
  // the current codebase, but an SDK upgrade could introduce them. Tag
  // the rethrow with `errorCode: 'INTERNAL'` so the outer
  // `classifyAndReport` branch (see `errors.ts`) buckets this as
  // INTERNAL rather than the much-less-actionable UNKNOWN — operators
  // grep logs by errorCode.
  let serialized: string;
  try {
    serialized = JSON.stringify(structured);
  } catch (err) {
    const wrapped = new Error(
      `buildSuccessResponse failed to serialize structured payload: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
    (wrapped as Error & { errorCode?: string }).errorCode = 'INTERNAL';
    throw wrapped;
  }

  return {
    structuredContent: structured,
    content: [{ type: 'text', text: serialized }],
  };
}
