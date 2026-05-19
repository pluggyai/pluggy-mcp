/**
 * Structured stderr event logger.
 *
 * Centralizes the `console.error(JSON.stringify({ ts, event, ...fields }))`
 * shape that appears across startup, security, and tool plumbing so the
 * format is consistent (timestamp + event name first, then per-site fields)
 * and a single grep target (`event=...`) keeps working.
 *
 * Stays out of `src/security/` so non-security callers (startup, shutdown,
 * lifecycle errors) can use it without pulling in security primitives.
 *
 * IMPORTANT: stdio MCP servers reserve stdout for JSON-RPC traffic — this
 * helper writes to stderr unconditionally. It is intentionally NOT used by
 * `src/security/audit.ts` (the audit line owns its own schema with an
 * explicit field-by-field copy) or by `src/util/errors.ts` (error log
 * lines follow a different `{ts, tool, operation, ...}` contract).
 */

/**
 * Emit one structured event line to stderr.
 *
 * Safety: never throws under normal conditions. The caller is responsible
 * for passing serializable values — non-serializable inputs (e.g. circular
 * objects) will surface as a `JSON.stringify` error to the caller, same as
 * before. We deliberately do NOT swallow such errors here because every
 * existing call site passes plain literals; hiding a serialization bug
 * would only make it harder to diagnose.
 */
export function logEvent(event: string, fields: Record<string, unknown> = {}): void {
  console.error(
    JSON.stringify({
      ts: new Date().toISOString(),
      event,
      ...fields,
    }),
  );
}
