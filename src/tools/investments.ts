/**
 * `listInvestments`, `getInvestment`, `listInvestmentTransactions` tools.
 *
 * The SDK exposes the three documented investment endpoints:
 *   - `fetchInvestments(itemId, type?, options?)` — list per Item
 *   - `fetchInvestment(id)` — single Investment by id
 *   - `fetchInvestmentTransactions(investmentId, options?)` — BUY/SELL
 *     movements for a specific investment position
 *
 * PII surface: the only owner-revealing field on `Investment` is `owner`
 * (the natural-person name). Everything else is asset-level data
 * (positions, rates, ISINs, brokerage notes) and not PII under LGPD.
 * We mask `owner` with `redactOwnerName` and wrap free-text strings
 * (`name`, `issuer`, `institution.name`, descriptions) in `<untrusted>`.
 *
 * Allowlist scope:
 *  - `listInvestments` takes `itemId` → pre-fetch allowlist check.
 *  - `getInvestment` / `listInvestmentTransactions` take opaque ids we
 *    cannot cheaply map back to a parent Item → NOT gated; tool
 *    descriptions document this loudly so the LLM knows.
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
  redactOwnerName,
  wrapUntrusted,
  UNTRUSTED_PREAMBLE,
  LOCAL_RATE_LIMITED_MESSAGE,
  ITEM_NOT_ALLOWED_MESSAGE,
} from '../security/index.js';

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const InvestmentInstitutionSchema = z.object({
  name: z.string().nullable(),
  number: z.string().nullable(),
});

const InvestmentMetadataSchema = z.object({
  taxRegime: z.string().nullable(),
  proposalNumber: z.string().nullable(),
  processNumber: z.string().nullable(),
});

const InvestmentSchema = z.object({
  id: z.string(),
  code: z.string().nullable(),
  issuerCNPJ: z.string().nullable(),
  number: z.string().nullable(),
  isin: z.string().nullable(),
  itemId: z.string(),
  type: z.string(),
  subtype: z.string().nullable(),
  // Free-text from the asset issuer / institution — wrapped in <untrusted>.
  name: z.string(),
  currencyCode: z.string(),
  date: z.string().nullable(),
  value: z.number().nullable(),
  quantity: z.number().nullable(),
  taxes: z.number().nullable(),
  taxes2: z.number().nullable(),
  balance: z.number(),
  amount: z.number().nullable(),
  amountWithdrawal: z.number().nullable(),
  amountProfit: z.number().nullable(),
  amountOriginal: z.number().nullable(),
  dueDate: z.string().nullable(),
  // Issuer free-text — wrapped.
  issuer: z.string().nullable(),
  issueDate: z.string().nullable(),
  purchaseDate: z.string().nullable(),
  rate: z.number().nullable(),
  rateType: z.string().nullable(),
  fixedAnnualRate: z.number().nullable(),
  lastMonthRate: z.number().nullable(),
  annualRate: z.number().nullable(),
  lastTwelveMonthsRate: z.number().nullable(),
  status: z.string().nullable(),
  metadata: InvestmentMetadataSchema.nullable(),
  // Owner — masked via `redactOwnerName` unless PLUGGY_MCP_REDACT=false.
  owner: z.string().nullable(),
  institution: InvestmentInstitutionSchema.nullable(),
});

const ExpensesSchema = z.object({
  serviceTax: z.number().nullable(),
  brokerageFee: z.number().nullable(),
  incomeTax: z.number().nullable(),
  other: z.number().nullable(),
  tradingAssetsNoticeFee: z.number().nullable(),
  maintenanceFee: z.number().nullable(),
  settlementFee: z.number().nullable(),
  clearingFee: z.number().nullable(),
  stockExchangeFee: z.number().nullable(),
  custodyFee: z.number().nullable(),
  operatingFee: z.number().nullable(),
});

const InvestmentTransactionSchema = z.object({
  id: z.string(),
  type: z.string().nullable(),
  // Free text — wrapped.
  description: z.string().nullable(),
  investmentId: z.string().nullable().optional(),
  quantity: z.number().nullable(),
  value: z.number().nullable(),
  amount: z.number().nullable(),
  date: z.string(),
  tradeDate: z.string().nullable(),
  brokerageNumber: z.string().nullable(),
  netAmount: z.number().nullable(),
  expenses: ExpensesSchema.nullable(),
  movementType: z.enum(['DEBIT', 'CREDIT']),
  agreedRate: z.number().nullable(),
});

// ---------------------------------------------------------------------------
// Mappers — typed against minimal structural shapes (same pattern as
// `transactions.ts`'s `TransactionLike`) so the masking surface is obvious.
// ---------------------------------------------------------------------------

type InvestmentLike = {
  id: string;
  code: string | null;
  issuerCNPJ: string | null;
  number: string | null;
  isin: string | null;
  itemId: string;
  type: string;
  subtype: string | null;
  name: string;
  currencyCode: string;
  date: Date | string | null;
  value: number | null;
  quantity: number | null;
  taxes: number | null;
  taxes2: number | null;
  balance: number;
  amount: number | null;
  amountWithdrawal: number | null;
  amountProfit: number | null;
  amountOriginal: number | null;
  dueDate: Date | string | null;
  issuer: string | null;
  issueDate: Date | string | null;
  purchaseDate: Date | string | null;
  rate: number | null;
  rateType: string | null;
  fixedAnnualRate: number | null;
  lastMonthRate: number | null;
  annualRate: number | null;
  lastTwelveMonthsRate: number | null;
  status: string | null;
  metadata: {
    taxRegime: string | null;
    proposalNumber: string | null;
    processNumber: string | null;
  } | null;
  owner: string | null;
  institution: { name: string | null; number: string | null } | null;
};

type InvestmentTransactionLike = {
  id: string;
  type: string | null;
  description: string | null;
  investmentId?: string | null;
  quantity: number | null;
  value: number | null;
  amount: number | null;
  date: Date | string;
  tradeDate: Date | string | null;
  brokerageNumber: string | null;
  netAmount: number | null;
  expenses: {
    serviceTax: number | null;
    brokerageFee: number | null;
    incomeTax: number | null;
    other: number | null;
    tradingAssetsNoticeFee: number | null;
    maintenanceFee: number | null;
    settlementFee: number | null;
    clearingFee: number | null;
    stockExchangeFee: number | null;
    custodyFee: number | null;
    operatingFee: number | null;
  } | null;
  movementType: 'DEBIT' | 'CREDIT';
  agreedRate: number | null;
};

function mapInvestment(
  i: InvestmentLike,
  redact: boolean,
): z.infer<typeof InvestmentSchema> {
  return {
    id: i.id,
    code: i.code,
    issuerCNPJ: i.issuerCNPJ,
    number: i.number,
    isin: i.isin,
    itemId: i.itemId,
    type: i.type,
    subtype: i.subtype,
    // Explicit null guard instead of `as string` — same posture as
    // `loans.ts:mapLoan.productName`.
    name: i.name != null ? (wrapUntrusted(i.name) ?? '') : '',
    currencyCode: i.currencyCode,
    date: dateToIso(i.date),
    value: i.value,
    quantity: i.quantity,
    taxes: i.taxes,
    taxes2: i.taxes2,
    balance: i.balance,
    amount: i.amount,
    amountWithdrawal: i.amountWithdrawal,
    amountProfit: i.amountProfit,
    amountOriginal: i.amountOriginal,
    dueDate: dateToIso(i.dueDate),
    issuer: wrapUntrusted(i.issuer),
    issueDate: dateToIso(i.issueDate),
    purchaseDate: dateToIso(i.purchaseDate),
    rate: i.rate,
    rateType: i.rateType,
    fixedAnnualRate: i.fixedAnnualRate,
    lastMonthRate: i.lastMonthRate,
    annualRate: i.annualRate,
    lastTwelveMonthsRate: i.lastTwelveMonthsRate,
    status: i.status,
    // Explicit field copy so a future SDK addition to `InvestmentMetadata`
    // doesn't silently leak — same defensive pattern as `accounts.ts`.
    metadata: i.metadata
      ? {
          taxRegime: i.metadata.taxRegime,
          proposalNumber: i.metadata.proposalNumber,
          processNumber: i.metadata.processNumber,
        }
      : null,
    // Owner is the only PII field on Investment — apply the same
    // first-name + last-initial masking we use on Accounts.
    owner: redact ? redactOwnerName(i.owner) : i.owner,
    institution: i.institution
      ? {
          name: wrapUntrusted(i.institution.name),
          number: i.institution.number,
        }
      : null,
  };
}

function mapInvestmentTransaction(
  t: InvestmentTransactionLike,
): z.infer<typeof InvestmentTransactionSchema> {
  return {
    id: t.id,
    type: t.type,
    description: wrapUntrusted(t.description),
    // Coalesce undefined → null so JSON.stringify keeps the key in the
    // envelope. Schema accepts both, but dropping it silently produces
    // an inconsistent shape across rows in the same response.
    investmentId: t.investmentId ?? null,
    quantity: t.quantity,
    value: t.value,
    amount: t.amount,
    date: dateToIso(t.date) ?? '',
    tradeDate: dateToIso(t.tradeDate),
    brokerageNumber: t.brokerageNumber,
    netAmount: t.netAmount,
    expenses: t.expenses
      ? {
          serviceTax: t.expenses.serviceTax,
          brokerageFee: t.expenses.brokerageFee,
          incomeTax: t.expenses.incomeTax,
          other: t.expenses.other,
          tradingAssetsNoticeFee: t.expenses.tradingAssetsNoticeFee,
          maintenanceFee: t.expenses.maintenanceFee,
          settlementFee: t.expenses.settlementFee,
          clearingFee: t.expenses.clearingFee,
          stockExchangeFee: t.expenses.stockExchangeFee,
          custodyFee: t.expenses.custodyFee,
          operatingFee: t.expenses.operatingFee,
        }
      : null,
    movementType: t.movementType,
    agreedRate: t.agreedRate,
  };
}

// ---------------------------------------------------------------------------
// Output shapes
// ---------------------------------------------------------------------------

// Single source of truth — see transactions.ts for rationale.
const ListInvestmentsOutputSchema = z.object({
  ok: z.boolean(),
  itemId: z.string().optional(),
  total: z.number().optional(),
  truncated: z.boolean().optional(),
  investments: z.array(InvestmentSchema).optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

const GetInvestmentOutputSchema = z.object({
  ok: z.boolean(),
  investment: InvestmentSchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

const ListInvestmentTransactionsOutputSchema = z.object({
  ok: z.boolean(),
  investmentId: z.string().optional(),
  total: z.number().optional(),
  truncated: z.boolean().optional(),
  transactions: z.array(InvestmentTransactionSchema).optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export function registerListInvestmentsTool(server: McpServer): void {
  const toolName = 'listInvestments';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'List investment positions (mutual funds, equities, fixed income, ' +
        'etc.) attached to a Pluggy Item. Asset names, issuer names, and ' +
        'institution names are wrapped in <untrusted>; the owner name is ' +
        'masked by default. ' +
        'When the server is configured with PLUGGY_ITEM_IDS, only itemIds ' +
        'in the allowlist will be fetched; others return a FORBIDDEN envelope.',
      inputSchema: {
        itemId: z
          .string()
          .uuid()
          .describe('The Pluggy Item id (UUID) whose investments should be listed.'),
      },
      outputSchema: ListInvestmentsOutputSchema.shape,
      annotations: {
        title: 'List Pluggy Investments',
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
        const page = await client.fetchInvestments(itemId);

        const { redact } = sec;
        const investments = page.results.map((i) =>
          mapInvestment(i as unknown as InvestmentLike, redact),
        );
        const total = page.total ?? investments.length;
        const totalPages = page.totalPages ?? 1;
        const truncated = totalPages > 1;

        if (truncated) {
          logEvent('truncated', {
            tool: toolName,
            itemIdHash: hashForAudit(itemId),
            total,
            returned: investments.length,
          });
        }

        const output = {
          ok: true as const,
          itemId,
          total,
          truncated,
          investments,
        };
        ensureOutputShape(ListInvestmentsOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchInvestments' },
          ListInvestmentsOutputSchema,
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

export function registerGetInvestmentTool(server: McpServer): void {
  const toolName = 'getInvestment';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'Fetch a single investment position by id. Owner name is masked ' +
        'by default; asset / issuer / institution names are wrapped in ' +
        '<untrusted>. ' +
        'Note: This tool takes a direct investmentId and is NOT gated by ' +
        'PLUGGY_ITEM_IDS. Use only with IDs you trust.',
      inputSchema: {
        investmentId: z
          .string()
          .uuid()
          .describe('The Pluggy investment id (UUID) to fetch.'),
      },
      outputSchema: GetInvestmentOutputSchema.shape,
      annotations: {
        title: 'Get Pluggy Investment',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ investmentId }) => {
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
        const i = await client.fetchInvestment(investmentId);
        const investment = mapInvestment(i as unknown as InvestmentLike, sec.redact);

        const output = { ok: true as const, investment };
        ensureOutputShape(GetInvestmentOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchInvestment' },
          GetInvestmentOutputSchema,
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
          ...hashArgsSafely({ investmentId }, ['investmentId']),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}

export function registerListInvestmentTransactionsTool(server: McpServer): void {
  const toolName = 'listInvestmentTransactions';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'List BUY/SELL/TAX/TRANSFER movements for a single investment ' +
        'position. None of the returned fields are PII (no payer/receiver, ' +
        'no card numbers); descriptions are wrapped in <untrusted>. ' +
        'Note: This tool takes a direct investmentId and is NOT gated by ' +
        'PLUGGY_ITEM_IDS. Use only with IDs you trust.',
      inputSchema: {
        investmentId: z
          .string()
          .uuid()
          .describe('The Pluggy investment id (UUID) to list transactions for.'),
      },
      outputSchema: ListInvestmentTransactionsOutputSchema.shape,
      annotations: {
        title: 'List Pluggy Investment Transactions',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ investmentId }) => {
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
        const page = await client.fetchInvestmentTransactions(investmentId);

        const transactions = page.results.map((t) =>
          mapInvestmentTransaction(t as unknown as InvestmentTransactionLike),
        );
        const total = page.total ?? transactions.length;
        const totalPages = page.totalPages ?? 1;
        const truncated = totalPages > 1;

        if (truncated) {
          logEvent('truncated', {
            tool: toolName,
            // Hash the investmentId for the same reason we hash itemIds in
            // truncation events: the raw value never reaches stderr.
            investmentIdHash: hashForAudit(investmentId),
            total,
            returned: transactions.length,
          });
        }

        const output = {
          ok: true as const,
          investmentId,
          total,
          truncated,
          transactions,
        };
        ensureOutputShape(ListInvestmentTransactionsOutputSchema, output, {
          tool: toolName,
        });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchInvestmentTransactions' },
          ListInvestmentTransactionsOutputSchema,
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
          ...hashArgsSafely({ investmentId }, ['investmentId']),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}
