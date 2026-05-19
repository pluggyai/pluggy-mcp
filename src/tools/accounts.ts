/**
 * `getAccounts` tool — list the bank / credit-card accounts attached to a
 * given Pluggy Item. Read-only: only calls `GET /accounts?itemId=...`.
 *
 * PII handling: this tool now exposes the three PII fields the SDK
 * surfaces (`number`, `owner`, `taxNumber`), but masked by default via
 * the helpers in `../security/redact`. Operators who explicitly need
 * unmasked data can either:
 *   - opt-out per server with `PLUGGY_MCP_REDACT=false` (logs a stderr
 *     WARN on startup), or
 *   - call the sibling tool `getRawAccountDetails(accountId)` for a
 *     single account; every call to that tool is audit-logged.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { getPluggyClient } from '../pluggy/client.js';
import { toIsoIfDate } from '../util/date.js';
import { ErrorCodeEnum, classifyAndReport } from '../util/errors.js';
import { ensureOutputShape, ensureErrorEnvelope } from '../util/outputShape.js';
import {
  buildErrorResponse,
  buildLiteralErrorResponse,
  buildSuccessResponse,
} from '../util/toolResponse.js';
import { loadSecurityConfig, isItemAllowed } from '../config.js';
import { logEvent } from '../util/log.js';
import { performance } from 'node:perf_hooks';
import {
  redactAccountNumber,
  redactCpf,
  redactOwnerName,
  checkRateLimit,
  audit,
  hashArgsSafely,
  hashForAudit,
  wrapUntrusted,
  UNTRUSTED_PREAMBLE,
  LOCAL_RATE_LIMITED_MESSAGE,
  ITEM_NOT_ALLOWED_MESSAGE,
} from '../security/index.js';

const BankDataSchema = z.object({
  transferNumber: z.string().nullable(),
  closingBalance: z.number().nullable(),
  automaticallyInvestedBalance: z.number().nullable(),
  overdraftUsedLimit: z.number().nullable(),
  unarrangedOverdraftAmount: z.number().nullable(),
});

const CreditDataSchema = z.object({
  level: z.string().nullable(),
  brand: z.string().nullable(),
  balanceCloseDate: z.union([z.string(), z.date()]).nullable(),
  balanceDueDate: z.union([z.string(), z.date()]).nullable(),
  availableCreditLimit: z.number().nullable(),
  balanceForeignCurrency: z.number().nullable(),
  minimumPayment: z.number().nullable(),
  creditLimit: z.number().nullable(),
  isLimitFlexible: z.boolean().nullable(),
  status: z.enum(['ACTIVE', 'BLOCKED', 'CANCELLED']).nullable(),
  holderType: z.enum(['MAIN', 'ADDITIONAL']).nullable(),
});

const AccountSchema = z.object({
  id: z.string().describe('Account id'),
  itemId: z.string().describe('Parent Pluggy Item id'),
  type: z.enum(['BANK', 'CREDIT']),
  subtype: z.enum(['SAVINGS_ACCOUNT', 'CHECKING_ACCOUNT', 'CREDIT_CARD']),
  balance: z.number().describe('Current balance in account currency'),
  name: z.string().describe('Account name / description'),
  marketingName: z.string().nullable(),
  currencyCode: z.string().describe('ISO 4217 currency code'),
  // PII fields — masked by default via the redact helpers. See
  // `getRawAccountDetails` for the unmasked variant.
  // SDK declares `number: string` (non-nullable); the redactor preserves
  // that — it returns null only when the input is null, which won't
  // happen for this field.
  number: z
    .string()
    .describe('Account number, masked to last 4 digits unless PLUGGY_MCP_REDACT=false'),
  owner: z
    .string()
    .nullable()
    .describe('Account holder, masked to first name + initial unless PLUGGY_MCP_REDACT=false'),
  taxNumber: z
    .string()
    .nullable()
    .describe('Holder CPF, masked to last 2 digits unless PLUGGY_MCP_REDACT=false'),
  bankData: BankDataSchema.nullable(),
  creditData: CreditDataSchema.nullable(),
});

// Flat output shape — `z.discriminatedUnion` can't be passed to
// `registerTool`'s `outputSchema` because the SDK wraps the argument in
// `z.object(...)`. Both branches still share a single discriminator
// (`ok`) and the tool callback emits a consistent shape per branch.
//
// Single source of truth — see `transactions.ts` for rationale. The raw
// shape passed to `registerTool({ outputSchema })` is derived from this
// schema's `.shape` so the validator used by `ensureOutputShape` and the
// shape the MCP SDK checks against cannot drift.
const GetAccountsOutputSchema = z.object({
  ok: z.boolean().describe('true on success, false when an error envelope is returned'),
  // Success-only fields.
  itemId: z.string().optional().describe('Echo of the requested itemId'),
  total: z.number().optional(),
  truncated: z
    .boolean()
    .optional()
    .describe('True when more results exist than were returned (page 1 only).'),
  accounts: z.array(AccountSchema).optional(),
  // Error-only fields.
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional().describe('Correlation id present in stderr logs'),
  message: z.string().optional().describe('Model-actionable error message'),
});

export function registerGetAccountsTool(server: McpServer): void {
  server.registerTool(
    'getAccounts',
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'Retrieve all accounts (bank, credit card, etc.) belonging to a given ' +
        'Pluggy Item. An Item represents one user-institution connection — call ' +
        '`listConnectors` first to discover institutions and create items via the ' +
        'Pluggy dashboard or your own backend to obtain an `itemId`. ' +
        'When the server is configured with PLUGGY_ITEM_IDS, only itemIds in the ' +
        'allowlist will be fetched; others return a FORBIDDEN envelope.',
      inputSchema: {
        itemId: z
          .string()
          .uuid()
          .describe('The Pluggy Item id (UUID) whose accounts should be fetched.'),
      },
      outputSchema: GetAccountsOutputSchema.shape,
      annotations: {
        title: 'Get Pluggy Accounts',
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
        // Skip the limiter entirely when the operator has disabled it
        // via `PLUGGY_MCP_RATELIMIT=false`. We still want this branch
        // present (rather than `if (sec.rateLimit) checkRateLimit(...)`)
        // because subsequent logic treats `rl.allowed` as the source of
        // truth and the typed shape stays uniform.
        const sec = loadSecurityConfig();
        const rl = sec.rateLimit
          ? checkRateLimit('getAccounts')
          : { allowed: true as const };
        if (!rl.allowed) {
          outcome = 'error';
          errorCode = 'LOCAL_RATE_LIMITED';
          rateLimitReason = rl.reason;
          return buildLiteralErrorResponse('LOCAL_RATE_LIMITED', LOCAL_RATE_LIMITED_MESSAGE);
        }

        // Allowlist check BEFORE building the client — keeps the SDK call
        // count and Pluggy's billable usage to zero for denied ids. Mirror
        // of the gate inside `getItem` / `listConsents`.
        if (!isItemAllowed(itemId)) {
          outcome = 'error';
          errorCode = 'FORBIDDEN';
          return buildLiteralErrorResponse('FORBIDDEN', ITEM_NOT_ALLOWED_MESSAGE);
        }

        const client = getPluggyClient();
        const page = await client.fetchAccounts(itemId);

        // Explicit field-by-field mapping. The three PII fields are run
        // through the redactor unless the operator has opted out via
        // `PLUGGY_MCP_REDACT=false` (a startup WARN line is emitted in
        // that case, see `logSecurityConfig`). Re-using the already-loaded
        // `sec` from the rate-limit guard above.
        const { redact } = sec;
        // Free-text fields (`name`, `marketingName`) come from the bank
        // and could in theory carry indirect prompt injection. Wrap them
        // in `<untrusted>` delimiters; identifiers, numbers, and enums
        // pass through untouched.
        const accounts = page.results.map((a) => ({
          id: a.id,
          itemId: a.itemId,
          type: a.type,
          subtype: a.subtype,
          balance: a.balance,
          name: wrapUntrusted(a.name) as string,
          marketingName: wrapUntrusted(a.marketingName),
          currencyCode: a.currencyCode,
          number: redact ? (redactAccountNumber(a.number) as string) : a.number,
          owner: redact ? redactOwnerName(a.owner) : a.owner,
          taxNumber: redact ? redactCpf(a.taxNumber) : a.taxNumber,
          // Explicit field copy of bankData so a future SDK addition can't
          // silently leak — and `transferNumber` is the bank-transfer
          // identifier (agency / account / digit), same PII tier as
          // `number`, so it gets the same redactor.
          bankData: a.bankData
            ? {
                transferNumber: redact
                  ? redactAccountNumber(a.bankData.transferNumber)
                  : a.bankData.transferNumber,
                closingBalance: a.bankData.closingBalance,
                automaticallyInvestedBalance: a.bankData.automaticallyInvestedBalance,
                overdraftUsedLimit: a.bankData.overdraftUsedLimit,
                unarrangedOverdraftAmount: a.bankData.unarrangedOverdraftAmount,
              }
            : null,
          // Explicit field-by-field copy so a future SDK addition to
          // `CreditData` can't silently leak into the LLM response. The
          // SDK returns Date for the balance dates; serialise to ISO
          // strings so the JSON envelope is stable and validates.
          creditData: a.creditData
            ? {
                level: a.creditData.level,
                brand: a.creditData.brand,
                balanceCloseDate: toIsoIfDate(a.creditData.balanceCloseDate),
                balanceDueDate: toIsoIfDate(a.creditData.balanceDueDate),
                availableCreditLimit: a.creditData.availableCreditLimit,
                balanceForeignCurrency: a.creditData.balanceForeignCurrency,
                minimumPayment: a.creditData.minimumPayment,
                creditLimit: a.creditData.creditLimit,
                isLimitFlexible: a.creditData.isLimitFlexible,
                status: a.creditData.status,
                holderType: a.creditData.holderType,
              }
            : null,
        }));

        const total = page.total ?? accounts.length;
        const truncated = total > accounts.length;

        if (truncated) {
          // Hashed itemId for consistency with audit events — raw itemIds
          // don't appear in stderr.
          logEvent('truncated', {
            tool: 'getAccounts',
            itemIdHash: hashForAudit(itemId),
            total,
            returned: accounts.length,
          });
        }

        const output = {
          ok: true as const,
          itemId,
          total,
          truncated,
          accounts,
        };
        ensureOutputShape(GetAccountsOutputSchema, output, { tool: 'getAccounts' });

        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        // Defensive envelope validation lives inside buildErrorResponse:
        // a future schema tightening that rejects the error envelope is
        // logged + falls back to a hardcoded INTERNAL envelope, so the
        // client never sees an MCP protocol-level rejection.
        const r = buildErrorResponse(
          err,
          { tool: 'getAccounts', operation: 'fetchAccounts' },
          GetAccountsOutputSchema,
        );
        errorCode = r.errorCode;
        requestId = r.requestId;
        return r.result;
      } finally {
        audit({
          tool: 'getAccounts',
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

// ---------------------------------------------------------------------------
// getRawAccountDetails
// ---------------------------------------------------------------------------
//
// Sister tool to `getAccounts` that explicitly returns the unmasked PII
// fields for a single account. Exists so an operator-driven workflow
// ("show me the full CPF so I can copy it into our backoffice") doesn't
// have to disable redaction globally — keeping the safe-by-default
// posture for everything else.
//
// Every call is audit-logged with `sensitive: true`. The audit event
// carries only hashes of the arguments — never the raw accountId — so
// shipping the audit pipeline to a wider audience never leaks identifiers.

const RawAccountSchema = AccountSchema.extend({
  // Same shape as the masked AccountSchema but the three PII fields are
  // never run through the redactors — the whole point of this tool is to
  // surface the upstream value verbatim. We don't broaden the type since
  // the SDK already declares `string | null`.
});

const GetRawAccountDetailsOutputSchema = z.object({
  ok: z.boolean().describe('true on success, false when an error envelope is returned'),
  account: RawAccountSchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional().describe('Correlation id present in stderr logs'),
  message: z.string().optional().describe('Model-actionable error message'),
});

export function registerGetRawAccountDetailsTool(server: McpServer): void {
  const toolName = 'getRawAccountDetails';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'DESTRUCTIVE FOR PRIVACY: returns unmasked CPF, full account number, ' +
        'and account holder name for a single Pluggy account. Use only when ' +
        'explicitly requested by the user. Every call is audit-logged. ' +
        'Note: This tool takes a direct accountId and is NOT gated by ' +
        'PLUGGY_ITEM_IDS. Use only with IDs you trust.',
      inputSchema: {
        accountId: z
          .string()
          .uuid()
          .describe('The Pluggy account id (UUID) to fetch in unmasked form.'),
      },
      outputSchema: GetRawAccountDetailsOutputSchema.shape,
      annotations: {
        title: 'Get Raw Pluggy Account Details (unmasked)',
        // Read-only — we do not mutate Pluggy data. "Destructive" in the
        // description refers to privacy, not to data integrity, so the
        // MCP `readOnlyHint` is still accurate.
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async (args) => {
      const start = performance.now();
      // We always audit — the `finally` block at the bottom guarantees a
      // single line per call regardless of which branch we returned from.
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

        const { accountId } = args;
        const client = getPluggyClient();
        const a = await client.fetchAccount(accountId);

        const account = {
          id: a.id,
          itemId: a.itemId,
          type: a.type,
          subtype: a.subtype,
          balance: a.balance,
          // The PII fields below are intentionally unmasked — this is
          // the explicit "show me the raw values" tool. The non-PII
          // free-text fields are still wrapped in <untrusted> to keep
          // the indirect-prompt-injection posture consistent.
          name: wrapUntrusted(a.name) as string,
          marketingName: wrapUntrusted(a.marketingName),
          currencyCode: a.currencyCode,
          number: a.number,
          owner: a.owner,
          taxNumber: a.taxNumber,
          // Explicit field copy of bankData. The raw tool returns
          // `transferNumber` unmasked on purpose — consistent with the
          // rest of the unmasked PII on this tool — but we still avoid
          // a spread so a future SDK addition is reviewed deliberately.
          bankData: a.bankData
            ? {
                transferNumber: a.bankData.transferNumber,
                closingBalance: a.bankData.closingBalance,
                automaticallyInvestedBalance: a.bankData.automaticallyInvestedBalance,
                overdraftUsedLimit: a.bankData.overdraftUsedLimit,
                unarrangedOverdraftAmount: a.bankData.unarrangedOverdraftAmount,
              }
            : null,
          creditData: a.creditData
            ? {
                level: a.creditData.level,
                brand: a.creditData.brand,
                balanceCloseDate: toIsoIfDate(a.creditData.balanceCloseDate),
                balanceDueDate: toIsoIfDate(a.creditData.balanceDueDate),
                availableCreditLimit: a.creditData.availableCreditLimit,
                balanceForeignCurrency: a.creditData.balanceForeignCurrency,
                minimumPayment: a.creditData.minimumPayment,
                creditLimit: a.creditData.creditLimit,
                isLimitFlexible: a.creditData.isLimitFlexible,
                status: a.creditData.status,
                holderType: a.creditData.holderType,
              }
            : null,
        };

        const output = { ok: true as const, account };
        ensureOutputShape(GetRawAccountDetailsOutputSchema, output, {
          tool: toolName,
        });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchAccount' },
          GetRawAccountDetailsOutputSchema,
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
          ...hashArgsSafely(args, ['accountId']),
          sensitive: true,
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}

// ---------------------------------------------------------------------------
// getAccount (masked single-account read)
// ---------------------------------------------------------------------------
//
// Sibling of `getAccounts` for the single-account case. PII fields
// (`number`, `owner`, `taxNumber`) are masked by the same helpers — for
// the unmasked variant, see `getRawAccountDetails` above. We intentionally
// do NOT mark this tool `sensitive` in the audit: the masked payload is
// no more revealing than `getAccounts` and we don't want sensitive-event
// log shipping to amplify ordinary reads.

const GetAccountOutputSchema = z.object({
  ok: z.boolean(),
  account: AccountSchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

export function registerGetAccountTool(server: McpServer): void {
  const toolName = 'getAccount';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'Fetch a single Pluggy account by id. The CPF (taxNumber), full ' +
        'account number, and owner name are MASKED by default — call ' +
        '`getRawAccountDetails` if you explicitly need the unmasked values ' +
        '(every such call is audit-logged). ' +
        'Note: This tool takes a direct accountId and is NOT gated by ' +
        'PLUGGY_ITEM_IDS. Use only with IDs you trust.',
      inputSchema: {
        accountId: z
          .string()
          .uuid()
          .describe('The Pluggy account id (UUID) to fetch.'),
      },
      outputSchema: GetAccountOutputSchema.shape,
      annotations: {
        title: 'Get Pluggy Account',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ accountId }) => {
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
        const a = await client.fetchAccount(accountId);

        const { redact } = sec;
        const account = {
          id: a.id,
          itemId: a.itemId,
          type: a.type,
          subtype: a.subtype,
          balance: a.balance,
          name: wrapUntrusted(a.name) as string,
          marketingName: wrapUntrusted(a.marketingName),
          currencyCode: a.currencyCode,
          number: redact ? (redactAccountNumber(a.number) as string) : a.number,
          owner: redact ? redactOwnerName(a.owner) : a.owner,
          taxNumber: redact ? redactCpf(a.taxNumber) : a.taxNumber,
          bankData: a.bankData
            ? {
                transferNumber: redact
                  ? redactAccountNumber(a.bankData.transferNumber)
                  : a.bankData.transferNumber,
                closingBalance: a.bankData.closingBalance,
                automaticallyInvestedBalance: a.bankData.automaticallyInvestedBalance,
                overdraftUsedLimit: a.bankData.overdraftUsedLimit,
                unarrangedOverdraftAmount: a.bankData.unarrangedOverdraftAmount,
              }
            : null,
          creditData: a.creditData
            ? {
                level: a.creditData.level,
                brand: a.creditData.brand,
                balanceCloseDate: toIsoIfDate(a.creditData.balanceCloseDate),
                balanceDueDate: toIsoIfDate(a.creditData.balanceDueDate),
                availableCreditLimit: a.creditData.availableCreditLimit,
                balanceForeignCurrency: a.creditData.balanceForeignCurrency,
                minimumPayment: a.creditData.minimumPayment,
                creditLimit: a.creditData.creditLimit,
                isLimitFlexible: a.creditData.isLimitFlexible,
                status: a.creditData.status,
                holderType: a.creditData.holderType,
              }
            : null,
        };

        const output = { ok: true as const, account };
        ensureOutputShape(GetAccountOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchAccount' },
          GetAccountOutputSchema,
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
          ...hashArgsSafely({ accountId }, ['accountId']),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}

// ---------------------------------------------------------------------------
// getRealTimeBalance
// ---------------------------------------------------------------------------
//
// Hits `GET /accounts/{id}/balance` via the SDK subclass added in
// `src/pluggy/client.ts`. This endpoint is Open-Finance-only — non-OF
// accounts will surface a 4xx from upstream, which our classifier
// translates into the right error envelope. The response carries only
// numbers + an ISO timestamp, no PII; no redaction needed.

const RealTimeBalanceSchema = z.object({
  balance: z.number(),
  blockedBalance: z.number().nullable(),
  automaticallyInvestedBalance: z.number().nullable(),
  currencyCode: z.string(),
  updateDateTime: z.string(),
});

const GetRealTimeBalanceOutputSchema = z.object({
  ok: z.boolean(),
  accountId: z.string().optional(),
  balance: RealTimeBalanceSchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

export function registerGetRealTimeBalanceTool(server: McpServer): void {
  const toolName = 'getRealTimeBalance';
  server.registerTool(
    toolName,
    {
      description:
        'Fetch the real-time balance for a Pluggy account directly from the ' +
        'financial institution, without triggering a full item sync. This ' +
        'endpoint is only available for Open Finance connectors — non-OF ' +
        'accounts will return a NOT_FOUND or FORBIDDEN error. The call ' +
        'counts against the institution-imposed rate limit shared with item ' +
        'syncs; expect 429s under load. ' +
        'Note: This tool takes a direct accountId and is NOT gated by ' +
        'PLUGGY_ITEM_IDS. Use only with IDs you trust.',
      inputSchema: {
        accountId: z
          .string()
          .uuid()
          .describe('The Pluggy account id (UUID) to refresh.'),
      },
      outputSchema: GetRealTimeBalanceOutputSchema.shape,
      annotations: {
        title: 'Get Real-Time Balance',
        readOnlyHint: true,
        openWorldHint: true,
        // Each call mutates Pluggy's cached balance for the account (the
        // docs explicitly say a subsequent GET /accounts/{id} reflects the
        // refreshed value). We still claim `idempotentHint: true` because
        // re-running with the same input produces the same conceptual
        // result — the operator's intent is unchanged across retries.
        idempotentHint: true,
      },
    },
    async ({ accountId }) => {
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
        const b = await client.fetchAccountBalance(accountId);

        const balance = {
          balance: b.balance,
          blockedBalance: b.blockedBalance ?? null,
          automaticallyInvestedBalance: b.automaticallyInvestedBalance ?? null,
          currencyCode: b.currencyCode,
          updateDateTime: b.updateDateTime,
        };

        const output = { ok: true as const, accountId, balance };
        ensureOutputShape(GetRealTimeBalanceOutputSchema, output, {
          tool: toolName,
        });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const safe = classifyAndReport(err, {
          tool: toolName,
          operation: 'fetchAccountBalance',
        });
        errorCode = safe.errorCode;
        requestId = safe.requestId;
        // Tool-specific override for 404/403 — the generic classifier
        // returns "the resource does not exist", but for this endpoint
        // the much more common cause is the connector not implementing
        // /accounts/{id}/balance. Keep the correlation id so an operator
        // can still cross-reference the stderr log.
        let message = safe.message;
        if (safe.errorCode === 'NOT_FOUND' || safe.errorCode === 'FORBIDDEN') {
          message =
            'Real-time balance is only available for Open Finance connectors. ' +
            'This account either does not exist or the connector does not ' +
            `support /accounts/{id}/balance. request-id=${safe.requestId}`;
        }
        // See note on the `getAccounts` catch block above.
        const errorOutput = ensureErrorEnvelope(
          GetRealTimeBalanceOutputSchema,
          {
            ok: false as const,
            errorCode: safe.errorCode,
            requestId: safe.requestId,
            message,
          },
          { tool: toolName },
        );
        return {
          isError: true,
          structuredContent: errorOutput,
          content: [{ type: 'text' as const, text: message }],
        };
      } finally {
        audit({
          tool: toolName,
          outcome,
          errorCode,
          durationMs: Math.round(performance.now() - start),
          ...hashArgsSafely({ accountId }, ['accountId']),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}
