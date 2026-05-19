/**
 * Allowlist-related user-facing constants.
 *
 * The allowlist enforcement logic lives in `../config.ts` (`isItemAllowed`,
 * `loadItemsAllowlist`) — that module owns the env parsing and caching.
 * This file owns only the LLM-facing message we emit on a denial, kept
 * separate so every tool that gates on the allowlist speaks with one
 * voice. Same posture as `LOCAL_RATE_LIMITED_MESSAGE` in `./rateLimit.ts`:
 * we never interpolate the offending id (that would leak the operator's
 * allow/deny decision into the LLM context).
 */

export const ITEM_NOT_ALLOWED_MESSAGE =
  'This itemId is not in PLUGGY_ITEM_IDS allowlist.';
