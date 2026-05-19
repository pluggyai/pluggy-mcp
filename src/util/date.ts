/**
 * Date serialization helpers shared across tool mappers.
 *
 * The Pluggy SDK returns ISO-string-valued fields as `Date` instances after
 * its JSON-with-Dates parsing. Our tool outputs are JSON envelopes validated
 * by Zod string schemas, so every SDK Date value must be normalized to an
 * ISO 8601 string before it reaches the output schema. Centralizing the
 * two shapes here keeps the conversion consistent across tools and gives
 * a single place to audit if the SDK changes its parsing rules.
 */

/**
 * Convert a nullable / undefined SDK date field to a nullable ISO string.
 *
 * - `null` / `undefined` collapse to `null` (consumers append `?? ''` when
 *   their schema requires a non-null string for required fields).
 * - `Date` instances are stringified via `toISOString()`.
 * - Strings pass through unchanged — the SDK occasionally hands us already-
 *   serialized values for fields it does not date-parse.
 */
export function dateToIso(value: Date | string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  return value;
}

/**
 * Convert a non-nullable SDK field that may be either a `Date` or a string
 * to an ISO string when it is a Date, otherwise pass through. Used for
 * schemas that accept `z.union([z.string(), z.date()])` so the JSON envelope
 * stays stable regardless of which shape the SDK returned.
 */
export function toIsoIfDate<T>(value: T | Date): T | string {
  return value instanceof Date ? value.toISOString() : value;
}
