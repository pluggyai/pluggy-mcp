/**
 * `listBills` / `getBill` tools — credit-card faturas (statements).
 *
 * Pluggy models each credit-card billing cycle as a `CreditCardBills`
 * record attached to an account. The tools below mirror the SDK's
 * `fetchCreditCardBills(accountId)` (list) and `fetchCreditCardBill(id)`
 * (single) calls.
 *
 * PII surface: bills carry only numbers, dates, and a `financeCharges`
 * array of category-coded fees with free-text `additionalInfo`. None of
 * the masked PII fields (CPF, account number, owner name) appear here,
 * so no redactor runs — but `additionalInfo` is institution-composed
 * free text and is wrapped in `<untrusted>`. Both tools take a direct
 * accountId / billId and are therefore NOT gated by `PLUGGY_ITEM_IDS`
 * (we cannot cheaply map either back to a parent item).
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
import { loadSecurityConfig } from '../config.js';
import { logEvent } from '../util/log.js';
import {
  audit,
  checkRateLimit,
  hashArgsSafely,
  hashForAudit,
  wrapUntrusted,
  UNTRUSTED_PREAMBLE,
  LOCAL_RATE_LIMITED_MESSAGE,
} from '../security/index.js';

const FinanceChargeSchema = z.object({
  id: z.string(),
  type: z.enum([
    'LATE_PAYMENT_REMUNERATIVE_INTEREST',
    'LATE_PAYMENT_FEE',
    'LATE_PAYMENT_INTEREST',
    'IOF',
    'OTHER',
  ]),
  amount: z.number(),
  currencyCode: z.string(),
  // Wrapped before reaching the schema; type stays string but the
  // <untrusted> delimiters tell the model to treat the contents as data.
  additionalInfo: z.string().nullable(),
});

const BillSchema = z.object({
  id: z.string(),
  dueDate: z.string(),
  totalAmount: z.number(),
  totalAmountCurrencyCode: z.string(),
  minimumPaymentAmount: z.number().nullable(),
  allowsInstallments: z.boolean().nullable(),
  financeCharges: z.array(FinanceChargeSchema),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/**
 * Minimal structural typedef of the SDK's CreditCardBills. We mirror the
 * SDK type fields we actually touch — same approach as `transactions.ts`'s
 * `TransactionLike`. Keeps the masking/wrapping surface obvious and gives
 * reviewers one place to check what we read.
 */
type BillLike = {
  id: string;
  dueDate: Date | string;
  totalAmount: number;
  totalAmountCurrencyCode: string;
  minimumPaymentAmount: number | null;
  allowsInstallments: boolean | null;
  financeCharges: Array<{
    id: string;
    type:
      | 'LATE_PAYMENT_REMUNERATIVE_INTEREST'
      | 'LATE_PAYMENT_FEE'
      | 'LATE_PAYMENT_INTEREST'
      | 'IOF'
      | 'OTHER';
    amount: number;
    currencyCode: string;
    additionalInfo: string | null;
  }>;
  createdAt: Date | string;
  updatedAt: Date | string;
};

function mapBill(b: BillLike): z.infer<typeof BillSchema> {
  return {
    id: b.id,
    dueDate: dateToIso(b.dueDate) ?? '',
    totalAmount: b.totalAmount,
    totalAmountCurrencyCode: b.totalAmountCurrencyCode,
    minimumPaymentAmount: b.minimumPaymentAmount,
    allowsInstallments: b.allowsInstallments,
    // Explicit field-by-field copy of each charge — a future SDK addition
    // (e.g. a `description` string) won't silently land in the LLM
    // context without a deliberate review.
    financeCharges: b.financeCharges.map((c) => ({
      id: c.id,
      type: c.type,
      amount: c.amount,
      currencyCode: c.currencyCode,
      additionalInfo: wrapUntrusted(c.additionalInfo),
    })),
    createdAt: dateToIso(b.createdAt) ?? '',
    updatedAt: dateToIso(b.updatedAt) ?? '',
  };
}

// Single source of truth — see transactions.ts for rationale.
const ListBillsOutputSchema = z.object({
  ok: z.boolean(),
  accountId: z.string().optional(),
  total: z.number().optional(),
  truncated: z.boolean().optional(),
  bills: z.array(BillSchema).optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

const GetBillOutputSchema = z.object({
  ok: z.boolean(),
  bill: BillSchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

export function registerListBillsTool(server: McpServer): void {
  const toolName = 'listBills';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'List credit-card bills (faturas / statements) for a given Pluggy ' +
        'account. Each bill carries the due date, total amount, minimum ' +
        'payment, and any finance charges. Free-text `additionalInfo` on ' +
        'each charge is wrapped in <untrusted> delimiters. ' +
        'Note: This tool takes a direct accountId and is NOT gated by ' +
        'PLUGGY_ITEM_IDS. Use only with IDs you trust.',
      inputSchema: {
        accountId: z
          .string()
          .uuid()
          .describe('The Pluggy credit-card account id (UUID) to list bills for.'),
      },
      outputSchema: ListBillsOutputSchema.shape,
      annotations: {
        title: 'List Pluggy Credit-Card Bills',
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
        const page = await client.fetchCreditCardBills(accountId);

        const bills = page.results.map((b) => mapBill(b as unknown as BillLike));
        const total = page.total ?? bills.length;
        const totalPages = page.totalPages ?? 1;
        // Same truncation idiom as `listConsents` — compare totalPages so
        // the flag survives a future SDK page-size change.
        const truncated = totalPages > 1;

        if (truncated) {
          logEvent('truncated', {
            tool: toolName,
            accountIdHash: hashForAudit(accountId),
            total,
            returned: bills.length,
          });
        }

        const output = {
          ok: true as const,
          accountId,
          total,
          truncated,
          bills,
        };
        ensureOutputShape(ListBillsOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchCreditCardBills' },
          ListBillsOutputSchema,
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

export function registerGetBillTool(server: McpServer): void {
  const toolName = 'getBill';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'Fetch a single credit-card bill (fatura) by id. Returns the due ' +
        'date, total amount, minimum payment, and finance charges; any ' +
        'free-text charge `additionalInfo` is wrapped in <untrusted>. ' +
        'Note: This tool takes a direct billId and is NOT gated by ' +
        'PLUGGY_ITEM_IDS. Use only with IDs you trust.',
      inputSchema: {
        billId: z
          .string()
          .uuid()
          .describe('The Pluggy credit-card bill id (UUID) to fetch.'),
      },
      outputSchema: GetBillOutputSchema.shape,
      annotations: {
        title: 'Get Pluggy Credit-Card Bill',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ billId }) => {
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
        const b = await client.fetchCreditCardBill(billId);
        const bill = mapBill(b as unknown as BillLike);

        const output = { ok: true as const, bill };
        ensureOutputShape(GetBillOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchCreditCardBill' },
          GetBillOutputSchema,
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
          ...hashArgsSafely({ billId }, ['billId']),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}
