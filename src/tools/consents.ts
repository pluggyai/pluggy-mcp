/**
 * `listConsents` / `getConsent` tools.
 *
 * Consents are the Open Finance authorization records that govern what
 * Pluggy is allowed to read on behalf of the user. None of the surfaced
 * fields are PII — they are UUIDs, product names, and timestamps — so no
 * redaction is needed. The free-text `products` / `openFinancePermissionsGranted`
 * arrays are stable enums controlled by Pluggy, so they don't get the
 * `<untrusted>` wrap either.
 *
 * `listConsents` takes an `itemId` and respects the PLUGGY_ITEM_IDS
 * allowlist; `getConsent` takes a consentId directly (Pluggy doesn't
 * give us a cheap way to map a consent back to its item without an
 * extra round-trip, so it is not allowlist-validated).
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { performance } from 'node:perf_hooks';
import { z } from 'zod';
import { getPluggyClient } from '../pluggy/client.js';
import { dateToIso } from '../util/date.js';
import { ErrorCodeEnum } from '../util/errors.js';
import { ensureOutputShape } from '../util/outputShape.js';
import {
  buildErrorResponse,
  buildLiteralErrorResponse,
  buildSuccessResponse,
} from '../util/toolResponse.js';
import { loadSecurityConfig, isItemAllowed } from '../config.js';
import { logEvent } from '../util/log.js';
import {
  audit,
  checkRateLimit,
  hashArgsSafely,
  hashForAudit,
  LOCAL_RATE_LIMITED_MESSAGE,
  ITEM_NOT_ALLOWED_MESSAGE,
} from '../security/index.js';

const ConsentSchema = z.object({
  id: z.string().describe('Consent id (UUID)'),
  itemId: z.string().describe('Parent Pluggy Item id'),
  products: z.array(z.string()).describe('Products the consent covers'),
  openFinancePermissionsGranted: z
    .array(z.string())
    .nullable()
    .describe('Open Finance permission strings granted'),
  createdAt: z.string(),
  expiresAt: z.string().nullable(),
  revokedAt: z.string().nullable(),
});

// Single source of truth — see transactions.ts for rationale.
const ListConsentsOutputSchema = z.object({
  ok: z.boolean().describe('true on success, false when an error envelope is returned'),
  itemId: z.string().optional().describe('Echo of the requested itemId'),
  total: z.number().optional(),
  truncated: z
    .boolean()
    .optional()
    .describe('True when more results exist than were returned (page 1 only).'),
  consents: z.array(ConsentSchema).optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

const GetConsentOutputSchema = z.object({
  ok: z.boolean(),
  consent: ConsentSchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

export function registerListConsentsTool(server: McpServer): void {
  const toolName = 'listConsents';
  server.registerTool(
    toolName,
    {
      description:
        'List Open Finance consents for a given Pluggy Item. Each consent ' +
        'describes which products and permissions were authorized, when ' +
        'authorization expires, and whether it has been revoked. When the ' +
        'server is configured with PLUGGY_ITEM_IDS, only ids in the allowlist ' +
        'will be queried; others return a FORBIDDEN envelope.',
      inputSchema: {
        itemId: z
          .string()
          .uuid()
          .describe('The Pluggy Item id (UUID) whose consents should be listed.'),
      },
      outputSchema: ListConsentsOutputSchema.shape,
      annotations: {
        title: 'List Pluggy Consents',
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

        const client = getPluggyClient();
        const page = await client.fetchConsents(itemId);

        const consents = page.results.map((c) => ({
          id: c.id,
          itemId: c.itemId,
          products: c.products,
          openFinancePermissionsGranted: c.openFinancePermissionsGranted,
          createdAt: dateToIso(c.createdAt) ?? '',
          expiresAt: dateToIso(c.expiresAt),
          revokedAt: dateToIso(c.revokedAt),
        }));

        const total = page.total ?? consents.length;
        // Compare totalPages instead of `total > consents.length` so the
        // truncated flag survives a future SDK default page-size change.
        const totalPages = page.totalPages ?? 1;
        const truncated = totalPages > 1;

        if (truncated) {
          logEvent('truncated', {
            tool: toolName,
            itemIdHash: hashForAudit(itemId),
            total,
            returned: consents.length,
          });
        }

        const output = {
          ok: true as const,
          itemId,
          total,
          truncated,
          consents,
        };
        ensureOutputShape(ListConsentsOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchConsents' },
          ListConsentsOutputSchema,
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
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}

export function registerGetConsentTool(server: McpServer): void {
  const toolName = 'getConsent';
  server.registerTool(
    toolName,
    {
      description:
        'Fetch a single Open Finance consent by id. Returns the products, ' +
        'permissions, expiration, and revocation status for the consent. ' +
        'Note: This tool takes a direct consentId and is NOT gated by ' +
        'PLUGGY_ITEM_IDS before the SDK call. When an allowlist is ' +
        'configured the response is filtered after fetching — the upstream ' +
        'round-trip still happens, but a consent whose parent itemId is ' +
        'not allowlisted returns a FORBIDDEN envelope.',
      inputSchema: {
        consentId: z
          .string()
          .uuid()
          .describe('The consent id (UUID) to fetch.'),
      },
      outputSchema: GetConsentOutputSchema.shape,
      annotations: {
        title: 'Get Pluggy Consent',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ consentId }) => {
      const start = performance.now();
      let outcome: 'success' | 'error' = 'success';
      let errorCode: string | undefined;
      let requestId: string | undefined;
      let rateLimitReason: 'PER_MINUTE' | 'PER_DAY' | undefined;
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

        const client = getPluggyClient();
        const c = await client.fetchConsent(consentId);

        // Post-fetch allowlist check: we cannot avoid the round-trip
        // because consentId doesn't reveal the parent itemId, but we
        // can refuse to surface the response when the resolved item is
        // outside the operator's allowlist. Better to leak nothing in
        // the LLM context than to honour a curiosity-driven probe.
        if (!isItemAllowed(c.itemId)) {
          outcome = 'error';
          errorCode = 'FORBIDDEN';
          return buildLiteralErrorResponse('FORBIDDEN', ITEM_NOT_ALLOWED_MESSAGE);
        }

        const consent = {
          id: c.id,
          itemId: c.itemId,
          products: c.products,
          openFinancePermissionsGranted: c.openFinancePermissionsGranted,
          createdAt: dateToIso(c.createdAt) ?? '',
          expiresAt: dateToIso(c.expiresAt),
          revokedAt: dateToIso(c.revokedAt),
        };

        const output = { ok: true as const, consent };
        ensureOutputShape(GetConsentOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchConsent' },
          GetConsentOutputSchema,
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
          ...hashArgsSafely({ consentId }, ['consentId']),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}
