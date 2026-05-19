/**
 * `listLoans` / `getLoan` tools.
 *
 * Loans (`fetchLoans(itemId)` / `fetchLoan(id)`) carry the Open Finance
 * contract structure: contract numbers, interest rates, scheduled
 * installments, warranties, and payment release history. None of the
 * canonical PII fields (CPF, account number, owner name) appear here,
 * but `cnpjConsignee` and several free-text "additional info" strings
 * exist — we wrap those in `<untrusted>` and pass numerics through.
 *
 * Allowlist scope:
 *  - `listLoans` takes `itemId` → pre-fetch allowlist check.
 *  - `getLoan` takes an opaque loanId — NOT gated (we cannot cheaply map
 *    it back to a parent Item without an extra round-trip). The tool
 *    description warns the LLM accordingly.
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
  wrapUntrusted,
  UNTRUSTED_PREAMBLE,
  LOCAL_RATE_LIMITED_MESSAGE,
  ITEM_NOT_ALLOWED_MESSAGE,
} from '../security/index.js';

// ---------------------------------------------------------------------------
// Schemas — flat & permissive on free-text enums (the Open Finance Brasil
// taxonomies are large and may evolve; we pass them through as strings).
// ---------------------------------------------------------------------------

const InterestRateSchema = z.object({
  taxType: z.string().nullable(),
  interestRateType: z.string().nullable(),
  taxPeriodicity: z.string().nullable(),
  calculation: z.string().nullable(),
  referentialRateIndexerType: z.string().nullable(),
  referentialRateIndexerSubType: z.string().nullable(),
  // Free-text — wrapped.
  referentialRateIndexerAdditionalInfo: z.string().nullable(),
  preFixedRate: z.number().nullable(),
  postFixedRate: z.number().nullable(),
  // Free-text — wrapped.
  additionalInfo: z.string().nullable(),
});

const ContractedFeeSchema = z.object({
  // Free-text — wrapped.
  name: z.string().nullable(),
  code: z.string().nullable(),
  chargeType: z.string().nullable(),
  charge: z.string().nullable(),
  amount: z.number().nullable(),
  rate: z.number().nullable(),
});

const ContractedFinanceChargeSchema = z.object({
  type: z.string().nullable(),
  // Free-text — wrapped.
  additionalInfo: z.string().nullable(),
  rate: z.number().nullable(),
});

const WarrantySchema = z.object({
  currencyCode: z.string().nullable(),
  type: z.string().nullable(),
  subtype: z.string().nullable(),
  amount: z.number().nullable(),
});

const InstallmentBalloonPaymentSchema = z.object({
  dueDate: z.string().nullable(),
  amount: z
    .object({
      value: z.number().nullable(),
      currencyCode: z.string().nullable(),
    })
    .nullable(),
});

const InstallmentsSchema = z.object({
  typeNumberOfInstallments: z.string().nullable(),
  totalNumberOfInstallments: z.number().nullable(),
  typeContractRemaining: z.string().nullable(),
  contractRemainingNumber: z.number().nullable(),
  paidInstallments: z.number().nullable(),
  dueInstallments: z.number().nullable(),
  pastDueInstallments: z.number().nullable(),
  balloonPayments: z.array(InstallmentBalloonPaymentSchema).nullable(),
});

const PaymentReleaseOverParcelFeeSchema = z.object({
  // Free-text — wrapped.
  name: z.string().nullable(),
  code: z.string().nullable(),
  amount: z.number().nullable(),
});

const PaymentReleaseOverParcelChargeSchema = z.object({
  type: z.string().nullable(),
  additionalInfo: z.string().nullable(),
  amount: z.number().nullable(),
});

const PaymentReleaseSchema = z.object({
  isOverParcelPayment: z.boolean().nullable(),
  installmentId: z.string().nullable(),
  paidDate: z.string().nullable(),
  currencyCode: z.string().nullable(),
  paidAmount: z.number().nullable(),
  overParcel: z
    .object({
      fees: z.array(PaymentReleaseOverParcelFeeSchema).nullable(),
      charges: z.array(PaymentReleaseOverParcelChargeSchema).nullable(),
    })
    .nullable(),
});

const PaymentsSchema = z.object({
  contractOutstandingBalance: z.number().nullable(),
  releases: z.array(PaymentReleaseSchema).nullable(),
});

const LoanSchema = z.object({
  id: z.string(),
  itemId: z.string(),
  contractNumber: z.string().nullable(),
  ipocCode: z.string().nullable(),
  // Free-text — wrapped.
  productName: z.string(),
  type: z.string().nullable(),
  date: z.string().nullable(),
  contractDate: z.string().nullable(),
  disbursementDates: z.array(z.string()).nullable(),
  settlementDate: z.string().nullable(),
  contractAmount: z.number().nullable(),
  currencyCode: z.string(),
  dueDate: z.string().nullable(),
  installmentPeriodicity: z.string().nullable(),
  // Free-text — wrapped.
  installmentPeriodicityAdditionalInfo: z.string().nullable(),
  firstInstallmentDueDate: z.string().nullable(),
  CET: z.number().nullable(),
  amortizationScheduled: z.string().nullable(),
  amortizationScheduledAdditionalInfo: z.string().nullable(),
  cnpjConsignee: z.string().nullable(),
  interestRates: z.array(InterestRateSchema).nullable(),
  contractedFees: z.array(ContractedFeeSchema).nullable(),
  contractedFinanceCharges: z.array(ContractedFinanceChargeSchema).nullable(),
  warranties: z.array(WarrantySchema).nullable(),
  installments: InstallmentsSchema.nullable(),
  payments: PaymentsSchema.nullable(),
});

// ---------------------------------------------------------------------------
// Mapper. Loans are deeply nested; we re-declare a structural type so the
// LSP can validate our field accesses against the SDK shape without
// importing the SDK type directly (same pattern as `transactions.ts`).
// ---------------------------------------------------------------------------

type DateLike = Date | string | null;

type LoanLike = {
  id: string;
  itemId: string;
  contractNumber: string | null;
  ipocCode: string | null;
  productName: string;
  type: string | null;
  date: DateLike;
  contractDate: DateLike;
  disbursementDates: Array<Date | string> | null;
  settlementDate: DateLike;
  contractAmount: number | null;
  currencyCode: string;
  dueDate: DateLike;
  installmentPeriodicity: string | null;
  installmentPeriodicityAdditionalInfo: string | null;
  firstInstallmentDueDate: DateLike;
  CET: number | null;
  amortizationScheduled: string | null;
  amortizationScheduledAdditionalInfo: string | null;
  cnpjConsignee: string | null;
  interestRates: Array<{
    taxType: string | null;
    interestRateType: string | null;
    taxPeriodicity: string | null;
    calculation: string | null;
    referentialRateIndexerType: string | null;
    referentialRateIndexerSubType: string | null;
    referentialRateIndexerAdditionalInfo: string | null;
    preFixedRate: number | null;
    postFixedRate: number | null;
    additionalInfo: string | null;
  }> | null;
  contractedFees: Array<{
    name: string | null;
    code: string | null;
    chargeType: string | null;
    charge: string | null;
    amount: number | null;
    rate: number | null;
  }> | null;
  contractedFinanceCharges: Array<{
    type: string | null;
    additionalInfo: string | null;
    rate: number | null;
  }> | null;
  warranties: Array<{
    currencyCode: string | null;
    type: string | null;
    subtype: string | null;
    amount: number | null;
  }> | null;
  installments: {
    typeNumberOfInstallments: string | null;
    totalNumberOfInstallments: number | null;
    typeContractRemaining: string | null;
    contractRemainingNumber: number | null;
    paidInstallments: number | null;
    dueInstallments: number | null;
    pastDueInstallments: number | null;
    balloonPayments: Array<{
      dueDate: DateLike;
      amount: { value: number | null; currencyCode: string | null } | null;
    }> | null;
  } | null;
  payments: {
    contractOutstandingBalance: number | null;
    releases: Array<{
      isOverParcelPayment: boolean | null;
      installmentId: string | null;
      paidDate: DateLike;
      currencyCode: string | null;
      paidAmount: number | null;
      overParcel: {
        fees: Array<{
          name: string | null;
          code: string | null;
          amount: number | null;
        }> | null;
        charges: Array<{
          type: string | null;
          additionalInfo: string | null;
          amount: number | null;
        }> | null;
      } | null;
    }> | null;
  } | null;
};

function mapLoan(l: LoanLike): z.infer<typeof LoanSchema> {
  return {
    id: l.id,
    itemId: l.itemId,
    // Institution-controlled identifiers — wrap so the institution can't
    // smuggle instruction-like content into the LLM channel via fields
    // shaped like a contract number.
    contractNumber: wrapUntrusted(l.contractNumber),
    ipocCode: wrapUntrusted(l.ipocCode),
    // Explicit null guard instead of `as string` — `productName` is
    // non-null per the SDK shape, but we don't want to lie to the
    // type system through a cast that would silently produce
    // `undefined` if the upstream ever stops sending the field.
    productName: l.productName != null ? (wrapUntrusted(l.productName) ?? '') : '',
    type: l.type,
    date: dateToIso(l.date),
    contractDate: dateToIso(l.contractDate),
    // The SDK ships `disbursementDates` as Date[] — normalize each entry.
    disbursementDates: l.disbursementDates
      ? l.disbursementDates.map((d) => dateToIso(d) ?? '')
      : null,
    settlementDate: dateToIso(l.settlementDate),
    contractAmount: l.contractAmount,
    currencyCode: l.currencyCode,
    dueDate: dateToIso(l.dueDate),
    installmentPeriodicity: l.installmentPeriodicity,
    installmentPeriodicityAdditionalInfo: wrapUntrusted(
      l.installmentPeriodicityAdditionalInfo,
    ),
    firstInstallmentDueDate: dateToIso(l.firstInstallmentDueDate),
    CET: l.CET,
    amortizationScheduled: l.amortizationScheduled,
    amortizationScheduledAdditionalInfo: wrapUntrusted(
      l.amortizationScheduledAdditionalInfo,
    ),
    cnpjConsignee: wrapUntrusted(l.cnpjConsignee),
    interestRates: l.interestRates
      ? l.interestRates.map((r) => ({
          taxType: r.taxType,
          interestRateType: r.interestRateType,
          taxPeriodicity: r.taxPeriodicity,
          calculation: r.calculation,
          referentialRateIndexerType: r.referentialRateIndexerType,
          referentialRateIndexerSubType: r.referentialRateIndexerSubType,
          referentialRateIndexerAdditionalInfo: wrapUntrusted(
            r.referentialRateIndexerAdditionalInfo,
          ),
          preFixedRate: r.preFixedRate,
          postFixedRate: r.postFixedRate,
          additionalInfo: wrapUntrusted(r.additionalInfo),
        }))
      : null,
    contractedFees: l.contractedFees
      ? l.contractedFees.map((f) => ({
          name: wrapUntrusted(f.name),
          code: f.code,
          chargeType: f.chargeType,
          charge: f.charge,
          amount: f.amount,
          rate: f.rate,
        }))
      : null,
    contractedFinanceCharges: l.contractedFinanceCharges
      ? l.contractedFinanceCharges.map((c) => ({
          type: c.type,
          additionalInfo: wrapUntrusted(c.additionalInfo),
          rate: c.rate,
        }))
      : null,
    warranties: l.warranties
      ? l.warranties.map((w) => ({
          currencyCode: w.currencyCode,
          type: w.type,
          subtype: w.subtype,
          amount: w.amount,
        }))
      : null,
    installments: l.installments
      ? {
          typeNumberOfInstallments: l.installments.typeNumberOfInstallments,
          totalNumberOfInstallments: l.installments.totalNumberOfInstallments,
          typeContractRemaining: l.installments.typeContractRemaining,
          contractRemainingNumber: l.installments.contractRemainingNumber,
          paidInstallments: l.installments.paidInstallments,
          dueInstallments: l.installments.dueInstallments,
          pastDueInstallments: l.installments.pastDueInstallments,
          balloonPayments: l.installments.balloonPayments
            ? l.installments.balloonPayments.map((b) => ({
                dueDate: dateToIso(b.dueDate),
                amount: b.amount
                  ? { value: b.amount.value, currencyCode: b.amount.currencyCode }
                  : null,
              }))
            : null,
        }
      : null,
    payments: l.payments
      ? {
          contractOutstandingBalance: l.payments.contractOutstandingBalance,
          releases: l.payments.releases
            ? l.payments.releases.map((r) => ({
                isOverParcelPayment: r.isOverParcelPayment,
                installmentId: r.installmentId,
                paidDate: dateToIso(r.paidDate),
                currencyCode: r.currencyCode,
                paidAmount: r.paidAmount,
                overParcel: r.overParcel
                  ? {
                      fees: r.overParcel.fees
                        ? r.overParcel.fees.map((f) => ({
                            name: wrapUntrusted(f.name),
                            code: f.code,
                            amount: f.amount,
                          }))
                        : null,
                      charges: r.overParcel.charges
                        ? r.overParcel.charges.map((c) => ({
                            type: c.type,
                            additionalInfo: wrapUntrusted(c.additionalInfo),
                            amount: c.amount,
                          }))
                        : null,
                    }
                  : null,
              }))
            : null,
        }
      : null,
  };
}

// ---------------------------------------------------------------------------
// Output shapes & tools
// ---------------------------------------------------------------------------

// Single source of truth — see `transactions.ts` for rationale.
const ListLoansOutputSchema = z.object({
  ok: z.boolean(),
  itemId: z.string().optional(),
  total: z.number().optional(),
  truncated: z.boolean().optional(),
  loans: z.array(LoanSchema).optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

const GetLoanOutputSchema = z.object({
  ok: z.boolean(),
  loan: LoanSchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

export function registerListLoansTool(server: McpServer): void {
  const toolName = 'listLoans';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'List loan / financing contracts for a Pluggy Item. Each contract ' +
        'includes interest rates, scheduled installments, warranties, and ' +
        'payment history. Free-text fields (product names, additional info ' +
        'strings, fee names) are wrapped in <untrusted>. ' +
        'When the server is configured with PLUGGY_ITEM_IDS, only itemIds ' +
        'in the allowlist will be fetched; others return a FORBIDDEN envelope.',
      inputSchema: {
        itemId: z
          .string()
          .uuid()
          .describe('The Pluggy Item id (UUID) whose loans should be listed.'),
      },
      outputSchema: ListLoansOutputSchema.shape,
      annotations: {
        title: 'List Pluggy Loans',
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
        const page = await client.fetchLoans(itemId);

        const loans = page.results.map((l) => mapLoan(l as unknown as LoanLike));
        const total = page.total ?? loans.length;
        const totalPages = page.totalPages ?? 1;
        const truncated = totalPages > 1;

        if (truncated) {
          logEvent('truncated', {
            tool: toolName,
            itemIdHash: hashForAudit(itemId),
            total,
            returned: loans.length,
          });
        }

        const output = {
          ok: true as const,
          itemId,
          total,
          truncated,
          loans,
        };
        ensureOutputShape(ListLoansOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchLoans' },
          ListLoansOutputSchema,
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

export function registerGetLoanTool(server: McpServer): void {
  const toolName = 'getLoan';
  server.registerTool(
    toolName,
    {
      description:
        UNTRUSTED_PREAMBLE +
        '\n\n' +
        'Fetch a single loan contract by id, including the full installment ' +
        'and payment-release schedule. Free-text fields are wrapped in ' +
        '<untrusted>. ' +
        'Note: This tool takes a direct loanId and is NOT gated by ' +
        'PLUGGY_ITEM_IDS. Use only with IDs you trust.',
      inputSchema: {
        loanId: z
          .string()
          .uuid()
          .describe('The Pluggy loan id (UUID) to fetch.'),
      },
      outputSchema: GetLoanOutputSchema.shape,
      annotations: {
        title: 'Get Pluggy Loan',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ loanId }) => {
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
        const l = await client.fetchLoan(loanId);
        const loan = mapLoan(l as unknown as LoanLike);

        const output = { ok: true as const, loan };
        ensureOutputShape(GetLoanOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchLoan' },
          GetLoanOutputSchema,
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
          ...hashArgsSafely({ loanId }, ['loanId']),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}
