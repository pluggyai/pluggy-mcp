/**
 * Tool registration barrel.
 *
 * Each per-domain module owns its own schemas and handler. Adding a tool
 * is a matter of writing one file and adding a call here.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  registerListConnectorsTool,
  registerGetConnectorTool,
} from './connectors.js';
import {
  registerGetAccountsTool,
  registerGetRawAccountDetailsTool,
  registerGetAccountTool,
  registerGetRealTimeBalanceTool,
} from './accounts.js';
import { registerGetItemTool } from './items.js';
import {
  registerListConsentsTool,
  registerGetConsentTool,
} from './consents.js';
import {
  registerListTransactionsTool,
  registerGetTransactionTool,
} from './transactions.js';
import {
  registerListCategoriesTool,
  registerGetCategoryTool,
} from './categories.js';
import { registerListBillsTool, registerGetBillTool } from './bills.js';
import {
  registerListInvestmentsTool,
  registerGetInvestmentTool,
  registerListInvestmentTransactionsTool,
} from './investments.js';
import { registerListLoansTool, registerGetLoanTool } from './loans.js';
import {
  registerGetIdentityByItemTool,
  registerGetIdentityTool,
} from './identity.js';
import {
  registerGetRecurringPaymentsTool,
  registerGetInsightsBookTool,
} from './intelligence.js';

export function registerAllTools(server: McpServer): void {
  // Connectors (no-PII reference data).
  registerListConnectorsTool(server);
  registerGetConnectorTool(server);
  // Items (operator-scoped via PLUGGY_ITEM_IDS).
  registerGetItemTool(server);
  registerListConsentsTool(server);
  registerGetConsentTool(server);
  // Accounts (masked-by-default; raw variant audit-logged).
  registerGetAccountsTool(server);
  registerGetAccountTool(server);
  registerGetRawAccountDetailsTool(server);
  registerGetRealTimeBalanceTool(server);
  // Transactions (heaviest PII surface; payer/receiver redacted, free
  // text wrapped in <untrusted>).
  registerListTransactionsTool(server);
  registerGetTransactionTool(server);
  // Categories (global taxonomy; no PII).
  registerListCategoriesTool(server);
  registerGetCategoryTool(server);
  // Bills (credit-card faturas; no PII, free-text fee info wrapped).
  registerListBillsTool(server);
  registerGetBillTool(server);
  // Investments (owner masked; asset/issuer/institution text wrapped).
  registerListInvestmentsTool(server);
  registerGetInvestmentTool(server);
  registerListInvestmentTransactionsTool(server);
  // Loans (no PII; deeply nested free-text wrapped throughout).
  registerListLoansTool(server);
  registerGetLoanTool(server);
  // Identity (HIGHEST PII; opt-in via PLUGGY_MCP_ENABLE_IDENTITY,
  // every call audit-logged with sensitive=true).
  registerGetIdentityByItemTool(server);
  registerGetIdentityTool(server);
  // Intelligence (premium enrichment + insights; raw fetch with
  // <untrusted> wrap on all free-text leaves).
  registerGetRecurringPaymentsTool(server);
  registerGetInsightsBookTool(server);
}
