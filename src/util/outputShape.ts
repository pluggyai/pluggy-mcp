/**
 * Output-shape pre-validator for tool success payloads.
 *
 * Why this lives in `util/` and not `security/`: it is a plain Zod check
 * paired with a sentinel-branded Error. It does no auditing, no
 * redaction, no rate limiting — moving it out of `security/audit.ts`
 * keeps that module focused on stderr audit emission.
 *
 * Why a Symbol brand instead of a string `code`: a string sentinel like
 * `'OUTPUT_SCHEMA_MISMATCH'` could collide with an upstream error that
 * happens to set the same `.code`. A `Symbol.for(...)` key is unique per
 * intern key and cannot be produced by an external library by accident.
 */

import type { ZodTypeAny } from 'zod';

/**
 * Brand key carried on Errors thrown by `ensureOutputShape`. Use
 * `Symbol.for` so multiple module instances (e.g. dual-bundling) still
 * resolve to the same symbol identity.
 */
export const OUTPUT_SCHEMA_MISMATCH = Symbol.for('pluggy-mcp.output-schema-mismatch');

/**
 * Pre-validate a payload against an outputSchema BEFORE the tool returns it.
 *
 * Why: when a tool's success path returns `{ structuredContent }` whose
 * shape drifts from the registered outputSchema, the MCP SDK rejects the
 * envelope after the handler has already exited. The audit `finally` has
 * by then emitted `outcome: success`, while the client receives an
 * `MCP error -32602`. The two views disagree.
 *
 * Calling this helper in the success path turns a shape drift into a
 * thrown Error that funnels through the existing `try/catch +
 * classifyAndReport` machinery, so:
 *   - the audit line correctly records `outcome=error`,
 *   - the LLM sees a stable `errorCode` and hardcoded message,
 *   - the upstream Zod issue list is captured in the stderr log only.
 */
export function ensureOutputShape<T extends ZodTypeAny>(
  schema: T,
  payload: unknown,
  context: { tool: string },
): void {
  const result = schema.safeParse(payload);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `${i.path.join('.')}: ${i.message}`)
      .join('; ');
    const err = new Error(
      `Output schema mismatch in ${context.tool}: ${issues}`,
    );
    (err as Error & { [OUTPUT_SCHEMA_MISMATCH]?: true })[OUTPUT_SCHEMA_MISMATCH] = true;
    throw err;
  }
}

/**
 * Validate an error envelope against the tool's declared outputSchema,
 * falling back to a hardcoded minimal envelope on mismatch.
 *
 * Why: `ensureOutputShape` is called on the success path so a shape drift
 * surfaces as a stable error envelope. The error envelope itself is
 * built from the `SafeError` returned by `classifyAndReport` plus
 * `ok: false`, and a future regression in the declared `outputSchema`
 * (e.g. tightening `message` to a `z.enum`) could make the envelope
 * fail validation too. Without this defense the MCP SDK would reject
 * the envelope post-handler and the LLM would see an `MCP error -32602`
 * instead of a structured failure.
 *
 * If the supplied envelope fails validation we:
 *  - emit a stderr WARN line so an operator notices the drift,
 *  - return a hardcoded `INTERNAL` envelope built only from literal
 *    values that the success-path schema is guaranteed to accept.
 *
 * The fallback envelope is INTENTIONALLY simple (no re-validation) to
 * avoid recursion: if a future change to the success schema also
 * rejects this hardcoded shape, the SDK will surface its own protocol
 * error — preferable to a stack overflow.
 */
export function ensureErrorEnvelope<T extends ZodTypeAny>(
  schema: T,
  envelope: { ok: false; errorCode: string; message: string; requestId?: string },
  context: { tool: string },
): { ok: false; errorCode: string; message: string; requestId?: string } {
  const result = schema.safeParse(envelope);
  if (result.success) return envelope;
  // Diagnostic stderr line — never on stdout (stdio JSON-RPC channel).
  // Keep the schema-issue summary out of the LLM-facing path; it stays
  // here for the operator.
  const issues = result.error.issues
    .map((i) => `${i.path.join('.')}: ${i.message}`)
    .join('; ');
  console.error(
    JSON.stringify({
      level: 'warn',
      tool: context.tool,
      event: 'error_envelope_shape_mismatch',
      issues,
    }),
  );
  return {
    ok: false,
    errorCode: 'INTERNAL',
    message:
      'Internal envelope shape mismatch — server failed to build a valid error response.',
    requestId: envelope.requestId,
  };
}
