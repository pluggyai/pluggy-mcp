# Security Policy

`pluggy-mcp` exposes a Brazilian Open Finance account aggregator to a Large
Language Model. The data it surfaces — CPF numbers, account numbers,
transaction histories, salary, related parties — is sensitive enough that
this document is required reading before deploying the server.

## Reporting vulnerabilities

Open a [GitHub Security Advisory](https://github.com/pluggyai/pluggy-mcp/security/advisories/new) for any suspected vulnerability. Do **not** file public GitHub issues for security bugs.

If you are uncertain whether something is a vulnerability, err on the side of using the private advisory channel.

## Threat model

This MCP server reads your bank account data and forwards it to an LLM.
The threat surfaces are:

### 1. Bank- and institution-controlled strings reaching the LLM

Merchant names, transaction descriptions, OFX memos, connector descriptions,
status messages, and similar fields ultimately originate from systems we
do not control — and an attacker who can influence one of those strings
can attempt to inject instructions into the LLM context (an *indirect
prompt injection*).

**Defenses:**

- Every upstream free-text field is wrapped in
  `<untrusted>...</untrusted>` delimiters before being returned to the
  LLM (`src/security/untrusted.ts`).
- Literal `<untrusted>` and `</untrusted>` substrings inside the source
  text are HTML-entity-escaped before wrapping, so an attacker cannot
  close the envelope.
- Every tool description carries a preamble (`UNTRUSTED_PREAMBLE`)
  instructing the LLM never to follow instructions found inside the
  delimiters.

### 2. PII in LLM context windows leaking via transcripts and logs

LLM hosts routinely persist conversation history. Anything we hand the
model can wind up in cloud-stored transcripts, in third-party telemetry,
or in user-shared screenshots.

**Defenses:**

- PII fields (CPF, full account numbers, card numbers, owner names,
  emails, phones, boleto digitable lines, CNPJ) are **masked by default**
  (`src/security/redact.ts`).
- Opting out via `PLUGGY_MCP_REDACT=false` is allowed but emits a loud
  startup `WARN` to stderr that names the disabled control.
- The `getRawAccountDetails` tool exists specifically so that a request
  for raw values is **explicit, audited, and separated** from the
  default-masked `getAccount`.

**Note on the text channel mirror:** per the MCP spec (2025-06-18,
"Structured Content"), tool responses now mirror `structuredContent` as
a JSON-serialized `TextContent` block so clients that only surface
`content[].text` (notably claude.ai today) can drive multi-step
workflows. Redacted values (CPF prefix-only, names truncated to
`First L.`, account `****1234`) flow through **both** channels — the
masking level is unchanged, but operators reasoning about "what reaches
cloud-stored transcripts" should know the LLM-facing text channel now
carries the same masked payload the structured channel already did.

### 3. Compromised LLM session issuing rogue tool calls

A jailbroken LLM, a malicious prompt, or a confused agent loop can issue
many tool calls in a short window — burning your Pluggy quota, leaking
data, or simply hammering the institution.

**Defenses:**

- Per-tool in-memory rate limit
  (`PLUGGY_MCP_RATELIMIT_PER_MIN`, `PLUGGY_MCP_RATELIMIT_PER_DAY` —
  defaults in the table below). Tools return a `LOCAL_RATE_LIMITED`
  envelope without calling the SDK when the budget is exhausted
  (`src/security/rateLimit.ts`). Because budgets are held in process
  memory, a host that crashes and is relaunched by the MCP client
  (Cursor / Claude Desktop / Codex) starts with full budgets. The same
  defaults apply to every tool, including high-PII
  `getRawAccountDetails`, `getIdentity`, and `getIdentityByItem`; lower
  the per-day budget for a tighter ceiling on those.
- `PLUGGY_ITEM_IDS` allowlist (operator-defined) constrains which
  Pluggy Items are queryable. Gated tools refuse out-of-list items
  before any SDK call; the `getInsightsBook` tool validates every
  itemId in its input array — any denial returns `FORBIDDEN`. An
  explicitly empty value is treated as **deny all** (fail-closed) and
  logs an `items_allowlist_empty` startup event so the misconfig is
  discoverable.
- Identity tools are **opt-in only**
  (`PLUGGY_MCP_ENABLE_IDENTITY=true`, strict `=== 'true'` comparison —
  `"1"`, `"yes"`, `"TRUE"`, typos all fail closed).
- **`sensitive: true` audit events are unbypassable.** Setting
  `PLUGGY_MCP_AUDIT=false` only suppresses non-sensitive lines; calls
  to the high-PII / intelligence tools — `getRawAccountDetails`,
  `getIdentityByItem`, `getIdentity`, `getRecurringPayments`,
  `getInsightsBook` — continue to log.

### 4. Credential exfiltration via env var dumps

A compromised dependency, debugger, or child process can attempt to
read `process.env` to steal credentials.

**Defenses:**

- `PLUGGY_CLIENT_ID` and `PLUGGY_CLIENT_SECRET` are **deleted from
  `process.env` after the first read** (`src/config.ts:loadPluggyConfig`).
  The credentials are then held only in the closed-over `cached`
  variable used by the Pluggy SDK client.
- Both credentials are scrubbed even when only one is present, so a
  partially-set env doesn't leak the half that was supplied.
- A child process spawned **before** the first config read inherits the
  env. The server triggers the read early in `main()` so this window
  is short.
- **Only credentials are scrubbed.** Security toggle vars
  (`PLUGGY_MCP_REDACT`, `PLUGGY_MCP_AUDIT`, `PLUGGY_MCP_RATELIMIT`,
  `PLUGGY_MCP_RATELIMIT_PER_MIN`, `PLUGGY_MCP_RATELIMIT_PER_DAY`,
  `PLUGGY_MCP_DEBUG`, `PLUGGY_MCP_ENABLE_IDENTITY`, `PLUGGY_ITEM_IDS`)
  remain in `process.env` after load — child processes spawned by the
  server (or by a dependency) will see them. Toggles are not secrets,
  but operators who rely on env-scrubbing for confidentiality should
  not assume the whole environment is wiped.

## Security defaults

| Control | Env var | Default | Posture |
| --- | --- | --- | --- |
| PII redaction | `PLUGGY_MCP_REDACT` | `true` | On — opt-out logs WARN. |
| Audit log | `PLUGGY_MCP_AUDIT` | `true` | On — sensitive events unbypassable. |
| Rate limit | `PLUGGY_MCP_RATELIMIT` | `true` | On — opt-out exposes Pluggy quota. |
| Per-minute budget | `PLUGGY_MCP_RATELIMIT_PER_MIN` | `30` | Conservative. |
| Per-day budget | `PLUGGY_MCP_RATELIMIT_PER_DAY` | `200` | Conservative. |
| Items allowlist | `PLUGGY_ITEM_IDS` | unset | No restriction. Empty = deny all. |
| Identity tools | `PLUGGY_MCP_ENABLE_IDENTITY` | `false` | Opt-in only. Strict `=== 'true'`. |
| Debug error bodies | `PLUGGY_MCP_DEBUG` | `0` | Off — upstream bodies can contain PII. |

## What this server does NOT defend against

- **Network exfiltration of audit logs.** The audit stream writes to
  stderr in cleartext. The operator is responsible for where stderr
  ends up (a file, a log shipper, a remote collector) and for whether
  that destination is itself trustworthy.
- **Operator misconfiguration** beyond the loud warnings we emit.
  Setting `PLUGGY_MCP_REDACT=false`, `PLUGGY_MCP_RATELIMIT=false`, or
  `PLUGGY_MCP_ENABLE_IDENTITY=true` is your choice; we surface the
  posture at startup but cannot prevent it.
- **Compromised Pluggy credentials.** If your client secret leaks,
  rotate it from the Pluggy dashboard. We cannot detect upstream abuse
  from inside the MCP server.
- **Compromised LLM client / host.** A malicious MCP host could read
  our stderr stream, intercept the JSON-RPC pipe, or harvest the data
  it received from a tool call. Defense lives in the host, not here.
- **Network-level attacks on the Pluggy API.** TLS validation is the
  Pluggy SDK's responsibility; we do not pin certificates.
- **Side channels in the LLM transcript.** Once data is in the model's
  context window, the host application controls where it goes next.
- **Write access to the process working directory.** A `.env` file in the
  server's CWD is loaded at startup (via `dotenv/config` in
  `src/config.ts`) and can set `PLUGGY_MCP_REDACT=false`,
  `PLUGGY_MCP_ENABLE_IDENTITY=true`, or any other toggle the MCP client
  did not already pass in `process.env`. Keep the working directory
  trusted; do not run `pluggy-mcp` out of a world-writable folder.

## What to do if you suspect compromise

1. **Stop the MCP server.** Quit the host (Cursor / Claude Desktop /
   Codex CLI) or kill the `pluggy-mcp` process.
2. **Rotate Pluggy credentials.** Issue a new client secret from the
   Pluggy dashboard and update your client config. The old secret will
   no longer authenticate.
3. **Revoke Open Finance consents** for affected items via the Pluggy
   dashboard so the upstream institutions stop returning data even if
   the credentials somehow survive.
4. **Review the audit log** (stderr capture of your MCP host) for
   `sensitive: true` events you did not authorize. The audit line
   carries the tool name, outcome, `errorCode`, and hashed arguments
   so you can correlate calls without re-exposing PII.
5. **Update the server** to pull in any fixes once a patched release
   is published.
