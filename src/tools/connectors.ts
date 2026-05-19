/**
 * `listConnectors` tool — surfaces all financial institutions Pluggy can
 * connect to. This is strictly read-only: it only calls `GET /connectors`.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { performance } from 'node:perf_hooks';
import { z } from 'zod';
import { getPluggyClient } from '../pluggy/client.js';
import { ErrorCodeEnum } from '../util/errors.js';
import { ensureOutputShape } from '../util/outputShape.js';
import {
  buildErrorResponse,
  buildLiteralErrorResponse,
  buildSuccessResponse,
} from '../util/toolResponse.js';
import { loadSecurityConfig } from '../config.js';
import { logEvent } from '../util/log.js';
import {
  audit,
  checkRateLimit,
  hashArgsSafely,
  wrapUntrusted,
  UNTRUSTED_PREAMBLE,
  LOCAL_RATE_LIMITED_MESSAGE,
} from '../security/index.js';

// Subset of the SDK's Connector shape — we expose only stable fields that
// are useful for an LLM picking a connector. The SDK adds new optional
// fields over time, so we keep this loose with `.passthrough()`-style
// helpers where appropriate.
const ConnectorSchema = z.object({
  id: z.number().describe('Pluggy connector id'),
  name: z.string().describe('Institution name'),
  institutionUrl: z.string().describe('Institution website URL'),
  imageUrl: z.string().describe('Institution logo URL'),
  primaryColor: z.string().describe('Brand color (hex)'),
  type: z
    .enum([
      'PERSONAL_BANK',
      'BUSINESS_BANK',
      'INVOICE',
      'INVESTMENT',
      'TELECOMMUNICATION',
      'DIGITAL_ECONOMY',
      'PAYMENT_ACCOUNT',
      'OTHER',
    ])
    .describe('Connector category'),
  country: z.string().describe('ISO country code, e.g. BR'),
  hasMFA: z.boolean(),
  oauth: z.boolean().optional(),
  isOpenFinance: z.boolean(),
  isSandbox: z.boolean(),
  supportsPaymentInitiation: z.boolean(),
  supportsScheduledPayments: z.boolean(),
  supportsSmartTransfers: z.boolean(),
  products: z.array(z.string()).describe('Products available on this connector'),
  health: z
    .object({
      status: z.enum(['ONLINE', 'OFFLINE', 'UNSTABLE']),
      stage: z.enum(['BETA']).nullable(),
    })
    .describe('Real-time connector availability'),
});

// `outputSchema` is wrapped by the SDK in `z.object(...)`, so we can't pass
// a `z.discriminatedUnion`. Instead we declare a flat shape that contains
// fields from both the success and error variants, with `ok` as the
// discriminator. Variant-specific fields are optional at the SDK level;
// the tool callback always emits one consistent shape per branch so
// downstream consumers can switch on `ok` reliably.
// Single source of truth — see `transactions.ts` for rationale.
const ListConnectorsOutputSchema = z.object({
  ok: z.boolean().describe('true on success, false when an error envelope is returned'),
  // Success-only fields.
  total: z.number().optional().describe('Total connectors reported by Pluggy'),
  truncated: z
    .boolean()
    .optional()
    .describe('True when more results exist than were returned (page 1 only).'),
  connectors: z.array(ConnectorSchema).optional(),
  // Error-only fields.
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional().describe('Correlation id present in stderr logs'),
  message: z.string().optional().describe('Model-actionable error message'),
});

export function registerListConnectorsTool(server: McpServer): void {
  server.registerTool(
    'listConnectors',
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'List all financial institutions (connectors) available through Pluggy. ' +
        'Use this to discover which banks, brokers, and other institutions a user ' +
        'can link, and to obtain the `connectorId` needed to create an item.',
      inputSchema: {
        // Intentionally empty — `GET /connectors` returns the full list and
        // server-side filters live on a follow-up tool (added in PR2+).
      },
      outputSchema: ListConnectorsOutputSchema.shape,
      annotations: {
        title: 'List Pluggy Connectors',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async () => {
      const start = performance.now();
      let outcome: 'success' | 'error' = 'success';
      let errorCode: string | undefined;
      let requestId: string | undefined;
      let rateLimitReason: 'PER_MINUTE' | 'PER_DAY' | undefined;
      try {
        const sec = loadSecurityConfig();
        const rl = sec.rateLimit
          ? checkRateLimit('listConnectors')
          : { allowed: true as const };
        if (!rl.allowed) {
          outcome = 'error';
          errorCode = 'LOCAL_RATE_LIMITED';
          rateLimitReason = rl.reason;
          return buildLiteralErrorResponse('LOCAL_RATE_LIMITED', LOCAL_RATE_LIMITED_MESSAGE);
        }

        const client = getPluggyClient();
        const page = await client.fetchConnectors();

        // Re-shape into our outputSchema — the SDK may add fields we don't
        // currently advertise; only forward what we documented. We wrap
        // the free-text `name` in `<untrusted>` delimiters: Pluggy
        // controls this string today but it ultimately surfaces an
        // institution-provided value, and treating it as data — not
        // instructions — is the safe posture. Other connector fields
        // are URLs / hex colors / enums and don't need wrapping.
        const connectors = page.results.map((c) => ({
          id: c.id,
          name: wrapUntrusted(c.name) ?? c.name,
          institutionUrl: c.institutionUrl,
          imageUrl: c.imageUrl,
          primaryColor: c.primaryColor,
          type: c.type,
          country: c.country,
          hasMFA: c.hasMFA,
          oauth: c.oauth,
          isOpenFinance: c.isOpenFinance,
          isSandbox: c.isSandbox,
          supportsPaymentInitiation: c.supportsPaymentInitiation,
          supportsScheduledPayments: c.supportsScheduledPayments,
          supportsSmartTransfers: c.supportsSmartTransfers,
          products: c.products,
          health: {
            status: c.health.status,
            stage: c.health.stage,
          },
        }));

        const total = page.total ?? connectors.length;
        const truncated = total > connectors.length;

        if (truncated) {
          // Signal to operators that pagination is missing — the LLM also
          // sees `truncated: true` in structuredContent (full pagination
          // ships in PR3+).
          logEvent('truncated', {
            tool: 'listConnectors',
            total,
            returned: connectors.length,
          });
        }

        const output = {
          ok: true as const,
          total,
          truncated,
          connectors,
        };
        ensureOutputShape(ListConnectorsOutputSchema, output, {
          tool: 'listConnectors',
        });

        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        // Must include `structuredContent` even on errors when an
        // `outputSchema` is declared — the SDK throws McpError otherwise.
        // buildErrorResponse handles validation; see helper for details.
        const r = buildErrorResponse(
          err,
          { tool: 'listConnectors', operation: 'fetchConnectors' },
          ListConnectorsOutputSchema,
        );
        errorCode = r.errorCode;
        requestId = r.requestId;
        return r.result;
      } finally {
        audit({
          tool: 'listConnectors',
          outcome,
          errorCode,
          durationMs: Math.round(performance.now() - start),
          // No-arg tool — `hashArgsSafely({}, [])` produces a stable empty
          // fingerprint without leaking any field names.
          ...hashArgsSafely({}, []),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}

// ---------------------------------------------------------------------------
// getConnector
// ---------------------------------------------------------------------------
//
// Fetches a single connector by its numeric id. Same field set as
// `listConnectors`. Connector ids are numeric integers, NOT UUIDs, so the
// input schema validates `z.number().int()`. No PII; same untrusted wrap
// for the free-text `name`. We deliberately do NOT surface the SDK's
// `credentials` array — that is internal Pluggy form metadata used to
// render a UI form, not useful to the LLM, and exposing it would expand
// the schema significantly without a corresponding caller benefit.

const GetConnectorOutputSchema = z.object({
  ok: z.boolean().describe('true on success, false when an error envelope is returned'),
  connector: ConnectorSchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional().describe('Correlation id present in stderr logs'),
  message: z.string().optional().describe('Model-actionable error message'),
});

export function registerGetConnectorTool(server: McpServer): void {
  const toolName = 'getConnector';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'Fetch a single Pluggy connector by id. Use this after ' +
        '`listConnectors` to inspect the products an institution supports ' +
        'and its real-time health.',
      inputSchema: {
        connectorId: z
          .number()
          .int()
          .positive()
          .describe('Numeric Pluggy connector id (NOT a UUID).'),
      },
      outputSchema: GetConnectorOutputSchema.shape,
      annotations: {
        title: 'Get Pluggy Connector',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ connectorId }) => {
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
        const c = await client.fetchConnector(connectorId);

        const connector = {
          id: c.id,
          name: wrapUntrusted(c.name) ?? c.name,
          institutionUrl: c.institutionUrl,
          imageUrl: c.imageUrl,
          primaryColor: c.primaryColor,
          type: c.type,
          country: c.country,
          hasMFA: c.hasMFA,
          oauth: c.oauth,
          isOpenFinance: c.isOpenFinance,
          isSandbox: c.isSandbox,
          supportsPaymentInitiation: c.supportsPaymentInitiation,
          supportsScheduledPayments: c.supportsScheduledPayments,
          supportsSmartTransfers: c.supportsSmartTransfers,
          products: c.products,
          health: {
            status: c.health.status,
            stage: c.health.stage,
          },
        };

        const output = { ok: true as const, connector };
        ensureOutputShape(GetConnectorOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchConnector' },
          GetConnectorOutputSchema,
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
          // connectorId is numeric — hashArgsSafely's allowlist only
          // copies stringy fields, so pass a [] allowlist; the argsHash
          // still includes the numeric value for correlation.
          ...hashArgsSafely({ connectorId }, []),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}
