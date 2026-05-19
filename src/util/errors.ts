/**
 * Safe error classification for tool handlers.
 *
 * Goals:
 *  - Never leak HTTP response bodies, stack traces, raw SDK errors, or
 *    anything that might contain customer data / secrets to the LLM.
 *  - Always log a structured single-line JSON entry to stderr (NEVER
 *    stdout — that channel is reserved for JSON-RPC traffic on stdio
 *    transports). Verbose dumps are gated behind PLUGGY_MCP_DEBUG=1.
 *  - Give the operator a correlatable request id they can grep in logs.
 *  - Map errors to a small enum the LLM can branch on (auth vs. rate
 *    limit vs. transient upstream failure) — much more useful than a
 *    single opaque "failed" message.
 */

import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { MissingCredentialsError } from '../pluggy/client.js';
import { OUTPUT_SCHEMA_MISMATCH } from './outputShape.js';

/**
 * Stable enum the LLM can pattern-match on. The values double as
 * documentation: each one corresponds to a well-defined upstream
 * situation, never to "something else went wrong".
 *
 * The Zod mirror (`ErrorCodeEnum`) is the canonical declaration; the TS
 * `ErrorCode` type is derived from it so the two cannot drift.
 */
export const ErrorCodeEnum = z.enum([
  'MISSING_CREDENTIALS',
  'UNAUTHORIZED',
  'FORBIDDEN',
  'NOT_FOUND',
  'RATE_LIMITED',
  'LOCAL_RATE_LIMITED',
  'UPSTREAM_5XX',
  'NETWORK',
  'INTERNAL',
  'UNKNOWN',
]);
export type ErrorCode = z.infer<typeof ErrorCodeEnum>;

/**
 * Envelope returned to the tool — embedded as `structuredContent` when
 * the tool result is the failure variant of its discriminated union.
 */
export interface SafeError {
  /** Stable, branchable category. */
  errorCode: ErrorCode;
  /** Short, model-actionable message. No secrets, no stack, no body. */
  message: string;
  /** UUID correlating this response with the stderr log line. */
  requestId: string;
}

/**
 * Heuristic: does an object look like a Pluggy data-API error body?
 * Pluggy rejects with the parsed JSON body itself, shaped like
 * `{ message, code: 404, codeDescription, errorId }`. The numeric `code`
 * is the HTTP status. Any OTHER upstream (a CDN, a proxy, a future SDK
 * version) that happens to set `code: <number>` for non-status meaning
 * must NOT be mis-classified — so we gate the `code`-as-status probe
 * behind the presence of one of Pluggy's discriminating fields.
 */
function looksLikePluggyErrorBody(
  b: unknown,
): b is { code: number; message: string; codeDescription?: unknown; errorId?: unknown } {
  // Array guard: arrays are `typeof 'object'` but never Pluggy bodies. The
  // numeric `code` probe below would otherwise accept e.g. `[401]` after a
  // future SDK quirk via array-index property access.
  if (!b || typeof b !== 'object' || Array.isArray(b)) return false;
  const obj = b as Record<string, unknown>;
  return (
    typeof obj.code === 'number' &&
    // NaN and Infinity are `typeof 'number'` — explicitly exclude them, plus
    // anything outside the valid HTTP status range. Without this gate a
    // future upstream returning `{ code: NaN, message: '...', errorId: '...' }`
    // would slip through and then fail STATUS_MAP lookup as `undefined`,
    // landing on UNKNOWN instead of the more specific NETWORK/INTERNAL paths.
    Number.isFinite(obj.code) &&
    obj.code >= 100 &&
    obj.code <= 599 &&
    typeof obj.message === 'string' &&
    ('codeDescription' in obj || 'errorId' in obj)
  );
}

/**
 * Best-effort extraction of HTTP status / code from heterogeneous error
 * shapes:
 *  - `got` HTTPError → `.response.statusCode`
 *  - pluggy-sdk data rejections → the parsed JSON body is the error
 *    itself, with `.statusCode` / `.code` / `.message` keys (see
 *    baseApi.js → `Promise.reject(body)`)
 *  - pluggy-sdk auth rejections → wrapped HTTPError → `.response.body.statusCode`
 *  - axios / `fetch`-style errors → `.response.status`
 *  - modern Node error chains (`AggregateError` etc) → `.cause.statusCode`
 *
 * All probes are checked defensively; the first match wins. We never
 * map a Pluggy string `code` (e.g. `"INVALID_FILTER"`) into our HTTP
 * status enum — those identifiers are not stable across SDK versions
 * and the LLM-facing message stays generic on purpose.
 */
function extractStatus(err: unknown): { status: number | null; code: string | null } {
  const anyErr = err as {
    response?: {
      statusCode?: number;
      status?: number;
      body?: { statusCode?: number; code?: string | number };
    };
    statusCode?: number;
    code?: string | number;
    body?: { statusCode?: number; code?: string | number };
    cause?: { statusCode?: number; code?: string | number };
  };
  // Gate the `code`-as-numeric-status probe behind a Pluggy-shape check.
  // Without the gate, a non-Pluggy upstream returning `{ code: 401 }`
  // with a non-HTTP meaning (CDN provider codes, etc.) would be
  // mis-classified as UNAUTHORIZED.
  const pluggyCodeStatus = looksLikePluggyErrorBody(anyErr)
    ? anyErr.code
    : looksLikePluggyErrorBody(anyErr?.body)
    ? anyErr.body?.code
    : looksLikePluggyErrorBody(anyErr?.response?.body)
    ? anyErr.response?.body?.code
    : undefined;
  // Same gate for `cause.code`: Node 18+ `fetch` and AggregateError surface
  // libuv errnos (e.g. `-4058` for ENOENT on Windows) as a numeric
  // `cause.code`. Without the Pluggy-shape check those negative integers
  // would short-circuit the status chain and silently mis-classify as
  // UNKNOWN — strings (ECONNRESET et al) still flow through the `code`
  // probe below for NETWORK.
  const causeCodeStatus = looksLikePluggyErrorBody(anyErr?.cause)
    ? (anyErr.cause as { code: number }).code
    : undefined;
  const status: number | null =
    [
      anyErr?.response?.statusCode,
      anyErr?.response?.status,
      anyErr?.response?.body?.statusCode,
      anyErr?.statusCode,
      anyErr?.body?.statusCode,
      anyErr?.cause?.statusCode,
      pluggyCodeStatus,
      causeCodeStatus,
    ].find((v): v is number => typeof v === 'number') ?? null;
  // Node 18+ `fetch` surfaces network errors as `TypeError` with the syscall
  // code on `cause.code` (e.g. `ENOTFOUND`, `ECONNREFUSED`), not at the top
  // level — probe both paths so `NETWORK` classification fires there too.
  const code: string | null =
    [
      anyErr?.code,
      anyErr?.body?.code,
      anyErr?.response?.body?.code,
      anyErr?.cause?.code,
    ].find((v): v is string => typeof v === 'string') ?? null;
  return { status, code };
}

// Pluggy's /auth handshake returns 400 — not 401 — for malformed or
// invalid credentials, and the SDK only surfaces a raw HTTPError for
// that pre-flight call (data calls have their non-2xx bodies caught
// and rejected as plain objects instead). Treating a bare 400 from a
// tool call as UNAUTHORIZED gives the model the right next step.
const STATUS_MAP: Record<number, { errorCode: ErrorCode; message: string }> = {
  400: {
    errorCode: 'UNAUTHORIZED',
    message: 'Pluggy rejected the credentials (400 on /auth). Verify PLUGGY_CLIENT_ID/SECRET.',
  },
  401: {
    errorCode: 'UNAUTHORIZED',
    message: 'Pluggy rejected the credentials (401). Rotate PLUGGY_CLIENT_ID/SECRET.',
  },
  403: {
    errorCode: 'FORBIDDEN',
    message: 'Pluggy returned 403 — premium feature or item not authorized for these credentials.',
  },
  404: {
    errorCode: 'NOT_FOUND',
    message: 'Pluggy returned 404 — the requested resource does not exist or was deleted.',
  },
  429: {
    errorCode: 'RATE_LIMITED',
    message: 'Pluggy returned 429 — rate limited. Back off and retry.',
  },
};

/**
 * Classify an arbitrary thrown value into a `SafeError` and emit a
 * single-line structured stderr log for the operator.
 *
 * The returned `message` is intentionally short and contains no stack,
 * no HTTP body, and no environment data. Set `PLUGGY_MCP_DEBUG=1` to
 * additionally dump the raw error object to stderr — useful when an
 * operator is actively diagnosing an issue, never on by default.
 *
 * SECURITY: never include upstream-derived strings in the user-facing
 * message. Pluggy error messages could contain markdown or
 * instruction-like content that would become an indirect prompt-injection
 * vector in the LLM context. Every branch below assigns a hardcoded
 * string constant — no interpolation of `err.message`, `err.response.body`,
 * or `(err as Error).message`. The stderr log can still carry upstream
 * fields (gated by PLUGGY_MCP_DEBUG), but the LLM-facing channel must
 * stay 100% server-controlled.
 */
export function classifyAndReport(
  err: unknown,
  ctx: { tool: string; operation?: string },
): SafeError {
  const requestId = randomUUID();
  const ts = new Date().toISOString();

  // 1) Missing credentials is a configuration problem, not an upstream
  //    failure — log a short line (no error object, nothing to redact)
  //    and return a distinct enum value so the model can prompt the
  //    operator to set env vars instead of suggesting a retry.
  if (err instanceof MissingCredentialsError) {
    console.error(
      JSON.stringify({
        ts,
        tool: ctx.tool,
        operation: ctx.operation ?? null,
        requestId,
        errorCode: 'MISSING_CREDENTIALS',
      }),
    );
    return {
      errorCode: 'MISSING_CREDENTIALS',
      requestId,
      message:
        'Pluggy credentials are not configured on this MCP server. Set PLUGGY_CLIENT_ID and PLUGGY_CLIENT_SECRET.',
    };
  }

  // 2) Internal shape-drift: a tool's success payload failed its own
  //    outputSchema. The thrown Error carries a Symbol brand so we can
  //    distinguish it from upstream Pluggy errors here without colliding
  //    with any string `.code` value an upstream library might set.
  //    Hardcoded user-facing message — never interpolate the Zod issue
  //    list, that text is for the operator's stderr log only.
  if (
    err instanceof Error &&
    (err as Error & { [OUTPUT_SCHEMA_MISMATCH]?: boolean })[OUTPUT_SCHEMA_MISMATCH] === true
  ) {
    const message =
      'Internal schema mismatch — server output did not match its declared shape. Please open an issue.';
    const errAsAny = err as { name?: unknown; message?: unknown };
    console.error(
      JSON.stringify({
        ts,
        tool: ctx.tool,
        operation: ctx.operation ?? null,
        requestId,
        errorCode: 'INTERNAL',
        // Keep `status` and `code` keys present (as null) so downstream
        // grep/jq pipelines see a uniform log-line shape across the
        // INTERNAL branch and the main classifier branch below.
        status: null,
        code: null,
        name: typeof errAsAny?.name === 'string' ? errAsAny.name : null,
        msg: typeof errAsAny?.message === 'string' ? errAsAny.message : null,
      }),
    );
    return {
      errorCode: 'INTERNAL',
      requestId,
      message: `${message} request-id=${requestId}`,
    };
  }

  // 3) Map HTTP / network errors to a stable enum.
  const { status, code } = extractStatus(err);
  let errorCode: ErrorCode = 'UNKNOWN';
  let message = 'Unexpected error talking to Pluggy. See server logs.';

  const mapped = status !== null ? STATUS_MAP[status] : undefined;
  if (mapped) {
    errorCode = mapped.errorCode;
    message = mapped.message;
  } else if (status !== null && status >= 500) {
    errorCode = 'UPSTREAM_5XX';
    message = 'Pluggy returned a transient server error. Retry shortly.';
  } else if (
    code === 'ETIMEDOUT' ||
    code === 'ECONNRESET' ||
    code === 'ENOTFOUND' ||
    code === 'ECONNREFUSED'
  ) {
    errorCode = 'NETWORK';
    // Hardcoded — do not interpolate `code` into the LLM-facing string,
    // even though it's constrained to a small allowlist above. The exact
    // syscall code is available to the operator in the stderr log.
    message = 'Network error talking to Pluggy. Retry shortly.';
  }

  // 4) Structured single-line stderr log. We deliberately do NOT include
  //    the response body or the stack: those are the channels through
  //    which secrets / customer data leak. The error name + message are
  //    enough to triage, and PLUGGY_MCP_DEBUG=1 unlocks the rest.
  const errAsAny = err as { name?: unknown; message?: unknown };
  const logLine = {
    ts,
    tool: ctx.tool,
    operation: ctx.operation ?? null,
    requestId,
    errorCode,
    status,
    code,
    name: typeof errAsAny?.name === 'string' ? errAsAny.name : null,
    msg: typeof errAsAny?.message === 'string' ? errAsAny.message : null,
  };
  console.error(JSON.stringify(logLine));

  if (process.env.PLUGGY_MCP_DEBUG === '1') {
    // Operator opt-in: dump the raw error (including any body / stack).
    // This is gated because the body can contain customer data.
    console.error('[PLUGGY_MCP_DEBUG] raw error:', err);
  }

  return { errorCode, requestId, message: `${message} request-id=${requestId}` };
}
