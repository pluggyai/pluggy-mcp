# pluggy-mcp

> A Model Context Protocol (MCP) server for the [Pluggy API](https://pluggy.ai)
> — Brazil's Open Finance data aggregator. Gives your LLM read-only access to
> your bank accounts, transactions, investments, credit cards, loans, and
> identity data.

## What it does

- Wraps Pluggy's REST API as an MCP server over the **stdio** transport.
- Exposes **24 read-only tools** spanning accounts, transactions, bills,
  investments, loans, identity, and Pluggy's premium intelligence APIs.
- **PII redaction on by default** — CPF, full account numbers, card numbers,
  owner names, emails, phones, boleto digitable lines, and CNPJ are masked
  before any data reaches the LLM context.
- **Per-tool rate limits** with conservative defaults so a runaway agent
  can't burn through your Pluggy quota.
- **Structured audit log** to stderr (one JSON line per call); high-risk
  tools (raw account, identity) emit `sensitive: true` events that **cannot
  be suppressed** by the audit toggle.
- **Untrusted-content wrapping** of every free-text field that originated
  from a third party (merchant, institution, OFX memo). Every tool
  description carries a preamble instructing the LLM never to follow
  instructions found inside `<untrusted>...</untrusted>` delimiters.
- **Optional allowlist** (`PLUGGY_ITEM_IDS`) restricts which Pluggy items
  the LLM can query — empty value means **deny all** (fail-closed).
- **Identity tools are opt-in**: the two tools that return CPF, addresses,
  phones, emails, salary, and related-party data are disabled until you
  explicitly set `PLUGGY_MCP_ENABLE_IDENTITY=true`.

```
MCP client (Cursor / Claude Desktop / Claude Code / Codex CLI)
        │  stdio JSON-RPC
        ▼
   pluggy-mcp
        │
        ▼
   rate-limit  ──▶  allowlist  ──▶  Pluggy SDK / rawFetch  ──▶  Pluggy REST API
                       (gated tools)         │                     │
                                             ▼                     ▼
                              redact → wrap <untrusted>      Open Finance /
                                             │              institution data
                                             ▼
                                  audit (emitted in `finally`)
```

## Quick start

### Option A: run from npm

> Note: the `pluggy-mcp` npm package is not yet published. Use Option B
> (local clone) until the first release lands.

```bash
npx -y pluggy-mcp
```

### Option B: run from a local clone

```bash
git clone https://github.com/pluggyai/pluggy-mcp.git
cd pluggy-mcp
npm install        # also runs `npm run build` via the `prepare` script
node dist/index.js
```

You will normally not invoke the server directly — your MCP client
([Cursor](#cursor), [Claude Desktop](#claude-desktop),
[Claude Code](#claude-code),
[OpenAI Codex CLI](#openai-codex-cli)) will launch it on demand.

## Configuration

### Get Pluggy credentials

1. Sign in to the [Pluggy dashboard](https://dashboard.pluggy.ai/).
2. Navigate to **Settings → API** to retrieve your `Client ID` and
   `Client Secret`.
3. (Optional) Use the dashboard to create or import **Items** — each item
   represents one user-institution connection. Copy the item UUIDs if you
   plan to scope the server with [`PLUGGY_ITEM_IDS`](#items-allowlist-pluggy_item_ids).

### Environment variables

<!-- keep this table in sync with src/config.ts and .env.example -->

| Variable | Required | Default | What it does | Security implication |
| --- | --- | --- | --- | --- |
| `PLUGGY_CLIENT_ID` | yes | — | Pluggy API client id. | Deleted from `process.env` after first read. |
| `PLUGGY_CLIENT_SECRET` | yes | — | Pluggy API client secret. | Deleted from `process.env` after first read. Treat as a password. |
| `PLUGGY_MCP_REDACT` | no | `true` | Mask PII (CPF, account numbers, card numbers, owner names, emails, phones, boleto lines, CNPJ) before returning to the LLM. | Setting `false` logs a loud startup `WARN`. Raw values then reach the LLM context. |
| `PLUGGY_MCP_AUDIT` | no | `true` | Emit one JSON audit line per tool call to stderr. | Setting `false` only suppresses **non-sensitive** lines. `sensitive: true` events are unbypassable. |
| `PLUGGY_MCP_RATELIMIT` | no | `true` | Enforce in-memory per-tool rate limits. | Setting `false` removes the only local guard against agent loops blowing your Pluggy quota. |
| `PLUGGY_MCP_RATELIMIT_PER_MIN` | no | `30` | Per-tool budget over a 60-second sliding window. | Budgets are **per tool**, **in-memory only**, and **reset on process restart**. The same default applies to every tool — including high-PII `getRawAccountDetails`, `getIdentity`, and `getIdentityByItem`; configure tighter limits if needed. Non-positive or non-numeric values fall back to the default and log `config_invalid`. |
| `PLUGGY_MCP_RATELIMIT_PER_DAY` | no | `200` | Per-tool budget over a 24-hour sliding window. | Same per-tool, in-memory, restart-reset behavior and fallback as the per-minute budget. |
| `PLUGGY_MCP_DEBUG` | no | `0` | Only the literal string `"1"` enables it (every other value — including `"true"`, `"yes"`, `"on"` — disables, inconsistent with the other toggles which accept everything-not-`"false"`). When enabled, dumps raw upstream error bodies and stacks to stderr. | Raw error bodies often include PII (CPF, account numbers, owner names) returned by the upstream institution. Keep off outside of active debugging. |
| `PLUGGY_ITEM_IDS` | no | unset | Comma-separated allowlist of Pluggy Item UUIDs. | Unset = no restriction. Present-but-empty = **deny all** (fail-closed). See below. |
| `PLUGGY_MCP_ENABLE_IDENTITY` | no | `false` | Opt-in switch for `getIdentityByItem` and `getIdentity`. Only the literal string `"true"` enables them. | Identity is the highest-PII surface. Every enabled call emits `sensitive: true` regardless of the audit toggle. |

A working `.env.example` is included in the [GitHub repository](https://github.com/pluggyai/pluggy-mcp/blob/main/.env.example) (not shipped via npm).

> **Note:** the server also loads a `.env` file from the **current working
> directory** at startup (via `dotenv/config` in `src/config.ts`). `dotenv`
> only fills variables that are not already present in `process.env`, so an
> env value passed by your MCP client wins over the `.env` file. Anyone who
> can write a `.env` next to the server's CWD can therefore flip
> `PLUGGY_MCP_REDACT=false`, `PLUGGY_MCP_ENABLE_IDENTITY=true`, etc., for
> any toggle the client didn't already set — keep the working directory
> trusted.

### Items allowlist (`PLUGGY_ITEM_IDS`)

`PLUGGY_ITEM_IDS` is an optional, comma-separated list of Pluggy Item UUIDs
the operator wants this MCP server scoped to. Get the UUIDs from the Items
list in the [Pluggy dashboard](https://dashboard.pluggy.ai/).

| Value | Meaning |
| --- | --- |
| Unset (no env var) | No restriction — every item is queryable. |
| Set, empty/whitespace | **Deny all.** Every gated tool returns `FORBIDDEN`. A `items_allowlist_empty` event is logged at startup so the misconfig is discoverable. |
| `uuid-a,uuid-b` | Only the listed items are queryable by gated tools. Case-insensitive. |

<!-- keep this list in sync with .env.example PLUGGY_ITEM_IDS comment -->

**Gated tools** (allowlist checked *before* any SDK call):

`getItem`, `listConsents`, `getAccounts`, `listInvestments`, `listLoans`,
`getIdentityByItem`, `getRecurringPayments`, `getInsightsBook` (every
itemId in the input array is validated; any denial returns `FORBIDDEN`
without calling the SDK).

**Not gated** (tools that take an `accountId`, `transactionId`,
`consentId`, `billId`, `investmentId`, `loanId`, or `identityId` —
because mapping those back to a parent item would require an extra
upstream round-trip): `getAccount`, `getRawAccountDetails`,
`getRealTimeBalance`, `listTransactions`, `getTransaction`,
`getConsent` (response is filtered after fetch),
`listBills`, `getBill`, `getInvestment`,
`listInvestmentTransactions`, `getLoan`, `getIdentity`.

> **Allowlist scope (read this).** `PLUGGY_ITEM_IDS` only gates tools
> that take a raw `itemId`. Tools that take `accountId`,
> `transactionId`, `consentId`, `investmentId`, `loanId`, `billId`, or
> `identityId` reach the SDK without an allowlist check — and those ids
> can be derived from a previously-allowed listing (`getAccounts`,
> `listInvestments`, etc.). If a child id ends up in the LLM's context
> from an earlier allowed call, subsequent calls using that id succeed
> regardless of the allowlist. Treat the allowlist as **partial
> containment**, not full authorization: it bounds *which items* a
> session can ever enumerate, but not which child resources stay
> reachable once an id leaks into context.

The allowlist is **cached at process startup**. Changes require a server
restart.

## MCP client setup

### Cursor

Cursor reads MCP server config from `~/.cursor/mcp.json` (or per-project
under `.cursor/mcp.json`). Add a `pluggy` entry pointing at your local
clone (until the npm package is published, `npx -y pluggy-mcp` returns 404):

```json
{
  "mcpServers": {
    "pluggy": {
      "command": "node",
      "args": ["/path/to/your/clone/of/pluggy-mcp/dist/index.js"],
      "env": {
        "PLUGGY_CLIENT_ID": "your-client-id",
        "PLUGGY_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

Once the npm package is published you can shorten this to:

```json
{
  "mcpServers": {
    "pluggy": {
      "command": "npx",
      "args": ["-y", "pluggy-mcp"],
      "env": {
        "PLUGGY_CLIENT_ID": "your-client-id",
        "PLUGGY_CLIENT_SECRET": "your-client-secret",
        "PLUGGY_ITEM_IDS": "YOUR_ITEM_ID_1,YOUR_ITEM_ID_2"
      }
    }
  }
}
```

Then open **Settings → MCP** in Cursor and verify the server is listed
and connected.

### Claude Desktop

Claude Desktop reads from a per-OS config file:

| OS | Path |
| --- | --- |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

*Linux is supported only via unofficial community builds (e.g., `claude-desktop-debian`); Anthropic does not officially ship Claude Desktop for Linux.*

Point the config at your local clone (until the npm package is published,
`npx -y pluggy-mcp` returns 404):

```json
{
  "mcpServers": {
    "pluggy": {
      "command": "node",
      "args": ["/path/to/your/clone/of/pluggy-mcp/dist/index.js"],
      "env": {
        "PLUGGY_CLIENT_ID": "your-client-id",
        "PLUGGY_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

Once the npm package is published you can shorten this to:

```json
{
  "mcpServers": {
    "pluggy": {
      "command": "npx",
      "args": ["-y", "pluggy-mcp"],
      "env": {
        "PLUGGY_CLIENT_ID": "your-client-id",
        "PLUGGY_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

Restart Claude Desktop after editing the file. Add the optional env vars
(`PLUGGY_ITEM_IDS`, `PLUGGY_MCP_ENABLE_IDENTITY`, etc.) the same way.

### Claude Code

Claude Code uses the `claude mcp add` CLI. Until `pluggy-mcp` is published to
npm, point at your local clone:

```bash
claude mcp add pluggy \
  --scope user \
  --env PLUGGY_CLIENT_ID=your-client-id \
  --env PLUGGY_CLIENT_SECRET=your-client-secret \
  -- node /path/to/your/clone/of/pluggy-mcp/dist/index.js
```

Once the npm package is published you can use:

```bash
claude mcp add pluggy \
  --scope user \
  --env PLUGGY_CLIENT_ID=your-client-id \
  --env PLUGGY_CLIENT_SECRET=your-client-secret \
  -- npx -y pluggy-mcp
```

Notes:
- All flags (`--scope`, `--env`, `--transport`) must come **before** the server name. `--` separates the server name from the command.
- `--scope user` makes the server available across every project (stored in `~/.claude.json`). Use `--scope local` (default) to scope it to the current project, or `--scope project` to write to a `.mcp.json` file shared via version control.
- Stdio is the default transport, so `--transport stdio` is optional.
- Verify with `claude mcp list` and `/mcp` inside a Claude Code session.

### OpenAI Codex CLI

Codex reads from `~/.codex/config.toml`. Add an `[mcp_servers.pluggy]`
table:

```toml
[mcp_servers.pluggy]
command = "npx"
args = ["-y", "pluggy-mcp"]

[mcp_servers.pluggy.env]
PLUGGY_CLIENT_ID = "your-client-id"
PLUGGY_CLIENT_SECRET = "your-client-secret"
# Optional:
# PLUGGY_ITEM_IDS = "YOUR_ITEM_ID_1,YOUR_ITEM_ID_2"
# WARNING: unlocks CPF, salary, addresses, related parties — read SECURITY.md first.
# PLUGGY_MCP_ENABLE_IDENTITY = "true"
```

Restart Codex after editing the file.

## Available tools

<!-- keep this table in sync with src/tools/index.ts -->

PII levels: **none** (no personal data), **low** (institution-controlled
free text, wrapped in `<untrusted>`), **high** (PII redacted by default;
raw available behind explicit opt-in).

### Connectors (reference data — no PII)

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `listConnectors` | — | All available institutions (banks, brokers, etc.) and their products / health. | low | Free-text names wrapped in `<untrusted>`. |
| `getConnector` | `connectorId` (number) | Single connector by id. | low | Same wrapping. |

### Items and consents

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `getItem` | `itemId` (UUID) | One user-institution connection; `status` / `executionStatus` indicate freshness. | none | **Allowlist-gated.** |
| `listConsents` | `itemId` (UUID) | Open Finance consents for the item (products, permissions, expiry, revocation). | none | **Allowlist-gated.** |
| `getConsent` | `consentId` | Single consent. | none | Not gated before fetch; response filtered after — denied items return `FORBIDDEN`. |

### Accounts and balances

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `getAccounts` | `itemId` (UUID) | All accounts for the item. | high (masked) | **Allowlist-gated.** CPF / account number / owner name masked by default. |
| `getAccount` | `accountId` (UUID) | One account. | high (masked) | Not gated. |
| `getRawAccountDetails` | `accountId` (UUID) | Unmasked CPF, full account number, holder name. | **high (UNMASKED)** | Not gated. Every call emits `sensitive: true` audit event. Use only on explicit user request. |
| `getRealTimeBalance` | `accountId` (UUID) | Live balance fetched directly from the institution. | none | Open Finance connectors only; counts against institution rate limit. Not gated. |

### Transactions

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `listTransactions` | `accountId` (UUID), optional date range, pagination | Paginated transactions. | high (masked) | Payer/receiver CPF + names masked; descriptions and merchant names wrapped in `<untrusted>`. Not gated. |
| `getTransaction` | `transactionId` (UUID) | Single transaction. | high (masked) | Same masking and wrapping. Not gated. |

### Categories

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `listCategories` | — | Pluggy's global category taxonomy. | none | Resolves `categoryId` values on transactions. |
| `getCategory` | `categoryId` (string) | One category by id. | none | — |

### Credit-card bills

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `listBills` | `accountId` (credit-card UUID) | Bills (faturas) — due date, total, minimum, charges. | low | Free-text `additionalInfo` on charges wrapped in `<untrusted>`. Not gated. |
| `getBill` | `billId` (UUID) | Single bill. | low | Same wrapping. Not gated. |

### Investments

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `listInvestments` | `itemId` (UUID) | Investment positions (funds, equities, fixed income, etc.). | high (masked) | **Allowlist-gated.** Owner name masked; asset/issuer/institution wrapped. |
| `getInvestment` | `investmentId` (UUID) | Single position. | high (masked) | Not gated. |
| `listInvestmentTransactions` | `investmentId` (UUID) | BUY / SELL / TAX / TRANSFER movements. | low | Descriptions wrapped. Not gated. |

### Loans

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `listLoans` | `itemId` (UUID) | Loan / financing contracts with rates, installments, warranties. | low | **Allowlist-gated.** Free text wrapped throughout. |
| `getLoan` | `loanId` (UUID) | Single loan including full installment schedule. | low | Not gated. |

### Identity (opt-in)

These tools are **disabled by default**. Set
`PLUGGY_MCP_ENABLE_IDENTITY=true` to enable.

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `getIdentityByItem` | `itemId` (UUID) | CPF, full name, addresses, phones, emails, salary, related parties. | **highest** | **Allowlist-gated.** SDK calls emit `sensitive: true`. Masking applies when `PLUGGY_MCP_REDACT=true`. |
| `getIdentity` | `identityId` | Same as above by opaque identity id. | **highest** | Not gated. Same audit + masking behavior. |

### Intelligence (premium)

Premium Pluggy feature — calls may return `403` if your account plan does
not include enrichment / insights.

| Tool | Input | Returns | PII | Notes |
| --- | --- | --- | --- | --- |
| `getRecurringPayments` | `itemId` (UUID) | Detected subscription-like recurring payments. | low | **Allowlist-gated.** Free text wrapped. |
| `getInsightsBook` | `itemIds` (UUID array) | Aggregated KPIs (cash flow, recurring income/expenses, account summaries) across one or many items. | low | **Allowlist-gated** — *any* denial in the input list returns `FORBIDDEN` without calling the SDK. |

## Security defaults

The defaults are tuned for a household / single-operator setup that wants
fast onboarding without giving the LLM raw PII. See the env table above
for the per-toggle defaults, and read [SECURITY.md](./SECURITY.md) for
the full threat model before exposing this server to any LLM client.

## Development

Requirements: **Node.js 22+**, npm.

```bash
git clone https://github.com/pluggyai/pluggy-mcp.git
cd pluggy-mcp
npm install        # `prepare` script also builds
npm run build      # tsc + chmod the entry script
npm run watch      # tsc --watch for active development
npm run inspect    # @modelcontextprotocol/inspector against the built server
```

The project deliberately ships **without an automated test suite**.
Verification is performed manually against the
[`@modelcontextprotocol/inspector`](https://www.npmjs.com/package/@modelcontextprotocol/inspector)
and a live Pluggy sandbox.

## Disclaimer

This project is **not officially affiliated with Pluggy**. It is a
community-maintained MCP server. Financial data is sensitive — review
[SECURITY.md](./SECURITY.md) before exposing this server to any LLM
client. Operators are responsible for safeguarding their Pluggy
credentials and for whatever is written to the audit log stream
(stderr).
