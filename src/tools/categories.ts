/**
 * `listCategories` / `getCategory` tools.
 *
 * Categories are the canonical taxonomy Pluggy assigns to transactions
 * (`categoryId` on a Transaction maps to one of these). They are global
 * (not per-item), entirely public, and contain no PII — so no redaction.
 *
 * The `description` / `parentDescription` strings are short Pluggy-
 * controlled enum-like labels, but we still wrap them in `<untrusted>`
 * as defense-in-depth: now that the MCP success response mirrors
 * `structuredContent` into the LLM-facing text channel
 * (`util/toolResponse.ts`), the cost of wrapping a vendor-controlled
 * string is trivial and matches what every other tool does for fields
 * like `marketingName` or connector `name`.
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
  LOCAL_RATE_LIMITED_MESSAGE,
} from '../security/index.js';

const CategorySchema = z.object({
  id: z.string().describe('Pluggy category id'),
  description: z.string().describe('Human-readable category name'),
  parentId: z.string().optional().describe('Parent category id, when nested'),
  parentDescription: z
    .string()
    .optional()
    .describe('Parent category description, when nested'),
});

// Single source of truth — see `transactions.ts` for rationale.
const ListCategoriesOutputSchema = z.object({
  ok: z.boolean(),
  total: z.number().optional(),
  truncated: z.boolean().optional(),
  categories: z.array(CategorySchema).optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

const GetCategoryOutputSchema = z.object({
  ok: z.boolean(),
  category: CategorySchema.optional(),
  errorCode: ErrorCodeEnum.optional(),
  requestId: z.string().optional(),
  message: z.string().optional(),
});

export function registerListCategoriesTool(server: McpServer): void {
  const toolName = 'listCategories';
  server.registerTool(
    toolName,
    {
      description:
        "List Pluggy's transaction category taxonomy. Use this to translate a " +
        '`categoryId` on a Transaction into a human-readable label, or to ' +
        'discover the full set of categories before driving downstream ' +
        'analytics. Categories are global and contain no PII.',
      inputSchema: {
        // No-arg; Pluggy returns the full taxonomy in a single page.
      },
      outputSchema: ListCategoriesOutputSchema.shape,
      annotations: {
        title: 'List Pluggy Categories',
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
          ? checkRateLimit(toolName)
          : { allowed: true as const };
        if (!rl.allowed) {
          outcome = 'error';
          errorCode = 'LOCAL_RATE_LIMITED';
          rateLimitReason = rl.reason;
          return buildLiteralErrorResponse('LOCAL_RATE_LIMITED', LOCAL_RATE_LIMITED_MESSAGE);
        }

        const client = getPluggyClient();
        const page = await client.fetchCategories();

        const categories = page.results.map((c) => ({
          id: c.id,
          description: wrapUntrusted(c.description) as string,
          parentId: c.parentId,
          parentDescription: wrapUntrusted(c.parentDescription) ?? undefined,
        }));

        const total = page.total ?? categories.length;
        const truncated = total > categories.length;

        if (truncated) {
          logEvent('truncated', {
            tool: toolName,
            total,
            returned: categories.length,
          });
        }

        const output = {
          ok: true as const,
          total,
          truncated,
          categories,
        };
        ensureOutputShape(ListCategoriesOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchCategories' },
          ListCategoriesOutputSchema,
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
          ...hashArgsSafely({}, []),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}

export function registerGetCategoryTool(server: McpServer): void {
  const toolName = 'getCategory';
  server.registerTool(
    toolName,
    {
      description:
        'Fetch a single Pluggy category by id. Useful when resolving a ' +
        'single `categoryId` from a Transaction without pulling the whole ' +
        'taxonomy.',
      inputSchema: {
        // Pluggy category ids are stable short strings (e.g. "01000000")
        // — NOT UUIDs. We accept any non-empty string here.
        categoryId: z.string().min(1).describe('The Pluggy category id.'),
      },
      outputSchema: GetCategoryOutputSchema.shape,
      annotations: {
        title: 'Get Pluggy Category',
        readOnlyHint: true,
        openWorldHint: true,
        idempotentHint: true,
      },
    },
    async ({ categoryId }) => {
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
        const c = await client.fetchCategory(categoryId);
        const category = {
          id: c.id,
          description: wrapUntrusted(c.description) as string,
          parentId: c.parentId,
          parentDescription: wrapUntrusted(c.parentDescription) ?? undefined,
        };

        const output = { ok: true as const, category };
        ensureOutputShape(GetCategoryOutputSchema, output, { tool: toolName });
        return buildSuccessResponse(output);
      } catch (err) {
        outcome = 'error';
        const r = buildErrorResponse(
          err,
          { tool: toolName, operation: 'fetchCategory' },
          GetCategoryOutputSchema,
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
          ...hashArgsSafely({ categoryId }, ['categoryId']),
          requestId,
          rateLimitReason,
        });
      }
    },
  );
}
