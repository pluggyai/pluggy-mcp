/**
 * `getItem` tool — fetch a single Pluggy Item by id. Read-only; only
 * calls `GET /items/{id}` via the SDK.
 *
 * An Item represents one user-institution connection. The response carries
 * connection state (`status`, `executionStatus`), the underlying connector,
 * and a couple of operator-supplied identifiers (`webhookUrl`,
 * `clientUserId`) that are surfaced cautiously — `clientUserId` is the
 * customer's identifier on the operator's side and is treated as PII.
 *
 * Items allowlist: when `PLUGGY_ITEM_IDS` is set, this tool refuses to
 * call the SDK for any itemId not in the configured list. Refusal goes
 * out as a `FORBIDDEN` envelope with a hardcoded message — no upstream
 * round-trip occurs.
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
import {
  audit,
  checkRateLimit,
  hashArgsSafely,
  wrapUntrusted,
  UNTRUSTED_PREAMBLE,
  LOCAL_RATE_LIMITED_MESSAGE,
  ITEM_NOT_ALLOWED_MESSAGE,
} from '../security/index.js';

const ItemProductStepWarningSchema = z.object({
  code: z.string(),
  // `message` and `providerMessage` are institution-composed free text.
  // Both are wrapped in <untrusted> in the mapper before they reach the
  // schema; the schema type stays `string` either way.
  message: z.string(),
  providerMessage: z.string().optional(),
});

const ItemProductStateSchema = z.object({
  isUpdated: z.boolean(),
  lastUpdatedAt: z.string().nullable(),
  warnings: z.array(ItemProductStepWarningSchema).optional(),
});

const ItemProductsStatusDetailSchema = z.object({
  accounts: ItemProductStateSchema.nullable(),
  creditCards: ItemProductStateSchema.nullable(),
  transactions: ItemProductStateSchema.nullable(),
  investments: ItemProductStateSchema.nullable(),
  investmentTransactions: ItemProductStateSchema.nullable(),
  identity: ItemProductStateSchema.nullable(),
  paymentData: ItemProductStateSchema.nullable(),
  loans: ItemProductStateSchema.nullable(),
  accountStatements: ItemProductStateSchema.nullable(),
});

const ItemErrorSchema = z.object({
  code: z.string(),
  message: z.string().nullable(),
});

const ItemSchema = z.object({
  id: z.string().describe('Pluggy Item id'),
  connectorId: z.number().describe('Underlying connector id'),
  connectorName: z.string().describe('Underlying connector name (institution)'),
  status: z.string().describe('Current item status (e.g. UPDATED, LOGIN_ERROR)'),
  executionStatus: z.string().describe('Current execution status'),
  statusDetail: ItemProductsStatusDetailSchema.nullable(),
  error: ItemErrorSchema.nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
  lastUpdatedAt: z.string().nullable(),
  // Operator-controlled identifier for the end-user — typically a UUID,
  // email, or numeric customer id. May carry PII (emails, CPFs), so we
  // wrap it in `<untrusted>` in the mapper before it reaches the schema;
  // the LLM must treat it as data, not as instructions.
  clientUserId: z
    .string()
    .nullable()
    .describe('Operator-supplied end-user id; wrapped in <untrusted> as it may carry PII.'),
  webhookUrl: z
    .string()
    .nullable()
    .describe('Operator-supplied webhook URL; wrapped in <untrusted>.'),
  consecutiveFailedLoginAttempts: z.number(),
  nextAutoSyncAt: z.string().nullable(),
  // We deliberately omit `userAction` and `parameter` from the surfaced
  // shape — they are MFA/credential-handshake payloads that don't belong
  // in an LLM context.
});

// Single source of truth — see `transactions.ts` for rationale.
const GetItemOutputSchema = z.object({
  ok: z.boolean().describe('true on success, false when an error envelope is returned'),
  item: ItemSchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional().describe('Correlation id present in stderr logs'),
  message: z.string().optional().describe('Model-actionable error message'),
});

/**
 * Map one product state, wrapping any institution-composed strings inside
 * `warnings[]` in `<untrusted>` so the LLM treats them as data. The shape
 * mirrors `ItemProductStateSchema`.
 */
type ProductStateLike = {
  isUpdated: boolean;
  lastUpdatedAt: Date | string | null;
  warnings?: Array<{ code: string; message: string; providerMessage?: string }>;
};
function mapProductState(
  state: ProductStateLike | null | undefined,
): z.infer<typeof ItemProductStateSchema> | null {
  if (state === null || state === undefined) return null;
  const warnings = state.warnings?.map((w) => ({
    code: w.code,
    message: wrapUntrusted(w.message) as string,
    providerMessage:
      w.providerMessage !== undefined
        ? wrapUntrusted(w.providerMessage) ?? undefined
        : undefined,
  }));
  return {
    isUpdated: state.isUpdated,
    lastUpdatedAt: dateToIso(state.lastUpdatedAt),
    warnings,
  };
}

/**
 * Map the full statusDetail object. Pluggy returns each product slot as
 * `null` when not requested or an `ItemProductState` otherwise; we keep
 * that shape so the LLM can see which products were attempted.
 */
type StatusDetailLike = {
  accounts: ProductStateLike | null;
  creditCards: ProductStateLike | null;
  transactions: ProductStateLike | null;
  investments: ProductStateLike | null;
  investmentTransactions: ProductStateLike | null;
  identity: ProductStateLike | null;
  paymentData: ProductStateLike | null;
  loans: ProductStateLike | null;
  accountStatements: ProductStateLike | null;
};
function mapStatusDetail(
  detail: StatusDetailLike | null | undefined,
): z.infer<typeof ItemProductsStatusDetailSchema> | null {
  if (detail === null || detail === undefined) return null;
  return {
    accounts: mapProductState(detail.accounts),
    creditCards: mapProductState(detail.creditCards),
    transactions: mapProductState(detail.transactions),
    investments: mapProductState(detail.investments),
    investmentTransactions: mapProductState(detail.investmentTransactions),
    identity: mapProductState(detail.identity),
    paymentData: mapProductState(detail.paymentData),
    loans: mapProductState(detail.loans),
    accountStatements: mapProductState(detail.accountStatements),
  };
}

export function registerGetItemTool(server: McpServer): void {
  const toolName = 'getItem';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'Fetch a single Pluggy Item by id. An Item represents one ' +
        'user-institution connection — its `status` and `executionStatus` ' +
        'tell you whether new data is available, whether the connection ' +
        'requires user action, or whether the credentials are stale. ' +
        'When the server is configured with PLUGGY_ITEM_IDS, only ids in ' +
        'the allowlist will be fetched; others return a FORBIDDEN envelope.',
      inputSchema: {
        itemId: z
          .string()
          .uuid()
          .describe('The Pluggy Item id (UUID) to fetch.'),
      },
      outputSchema: GetItemOutputSchema.shape,
      annotations: {
        title: 'Get Pluggy Item',
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

        // Allowlist check BEFORE building the client — keeps the SDK call
        // count and Pluggy's billable usage to zero for denied ids.
        if (!isItemAllowed(itemId)) {
          outcome = 'error';
          errorCode = 'FORBIDDEN';
          return buildLiteralErrorResponse('FORBIDDEN', ITEM_NOT_ALLOWED_MESSAGE);
        }

        const client = getPluggyClient();
        const it = await client.fetchItem(itemId);

        // `clientUserId` and `webhookUrl` are operator-controlled, but
        // both may carry PII (emails, CPFs) or untrusted text. Wrap them
        // in `<untrusted>` so the LLM treats them as data, never as
        // instructions. Redaction primitives don't apply — these are not
        // bank-supplied PII fields with a known shape.
        const item = {
          id: it.id,
          connectorId: it.connector.id,
          connectorName: wrapUntrusted(it.connector.name) as string,
          status: it.status,
          executionStatus: it.executionStatus,
          statusDetail: mapStatusDetail(
            it.statusDetail as StatusDetailLike | null | undefined,
          ),
          // Surface the `error` field so the LLM can branch on a finished
          // failure state. The `message` is institution-composed free
          // text — wrap to keep the LLM from treating it as instructions.
          error: it.error
            ? { code: it.error.code, message: wrapUntrusted(it.error.message ?? null) }
            : null,
          createdAt: dateToIso(it.createdAt) ?? '',
          updatedAt: dateToIso(it.updatedAt) ?? '',
          lastUpdatedAt: dateToIso(it.lastUpdatedAt),
          clientUserId: wrapUntrusted(it.clientUserId),
          webhookUrl: wrapUntrusted(it.webhookUrl),
          consecutiveFailedLoginAttempts: it.consecutiveFailedLoginAttempts,
          nextAutoSyncAt: dateToIso(it.nextAutoSyncAt),
        };

        const output = { ok: true as const, item };
        ensureOutputShape(GetItemOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchItem' },
          GetItemOutputSchema,
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
