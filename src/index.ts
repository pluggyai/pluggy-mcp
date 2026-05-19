#!/usr/bin/env node
/**
 * MCP stdio entry point for pluggy-mcp.
 *
 * IMPORTANT: stdio MCP servers MUST keep stdout reserved for JSON-RPC
 * traffic. All logging here goes to stderr (`console.error`).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SERVER_INFO, loadPluggyConfig, logSecurityConfig } from './config.js';
import { registerAllTools } from './tools/index.js';
import { logEvent } from './util/log.js';

async function main(): Promise<void> {
  // Process-level safety net. We split policy between the two channels:
  //  - unhandledRejection: log only. A missing `.catch()` should not abort
  //    an active tool call — the stdio pipe must stay open so the host can
  //    surface the error and the operator can grep stderr for `event=...`.
  //  - uncaughtException: log and exit. Per Node.js docs, an uncaught
  //    exception leaves the process in an unknown state; the safest move
  //    is to exit so the MCP host can restart the server cleanly.
  process.on('unhandledRejection', (reason) => {
    logEvent('unhandledRejection', { reason: String(reason) });
    // Intentionally do NOT exit — a missing .catch should not abort mid-tool-call.
  });
  process.on('uncaughtException', (err) => {
    logEvent('uncaughtException', {
      name: err?.name ?? null,
      message: err?.message ?? null,
    });
    // Per Node.js docs, uncaught exceptions mean the process is in an unknown state.
    // Exit so the MCP host can restart the server cleanly.
    process.exit(1);
  });

  const server = new McpServer({
    name: SERVER_INFO.name,
    version: SERVER_INFO.version,
  });

  registerAllTools(server);

  // Surface the resolved security toggles once at startup. Tools read the
  // same loadSecurityConfig() so the line below documents the truth they
  // will observe at runtime — and warns the operator if redaction is off.
  logSecurityConfig();

  // Surface a startup hint to the operator without crashing — the server
  // can still serve `tools/list`, and individual tools will return a safe
  // error if they're invoked without credentials.
  if (!loadPluggyConfig()) {
    console.error(
      '[pluggy-mcp] PLUGGY_CLIENT_ID and/or PLUGGY_CLIENT_SECRET are not set. ' +
        'Tools will return errors until both are configured.',
    );
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[pluggy-mcp] ${SERVER_INFO.name} v${SERVER_INFO.version} ready on stdio.`);

  // Graceful shutdown: respect MCP host lifecycle signals so any in-flight
  // requests get a chance to finish and the stdio pipe is closed cleanly.
  // A once-only guard prevents a double-signal (e.g. Ctrl-C twice) from
  // racing through `server.close()` twice.
  let shuttingDown = false;
  async function shutdown(signal: string): Promise<void> {
    if (shuttingDown) return;
    shuttingDown = true;
    logEvent('shutdown', { signal });
    try {
      await server.close();
    } catch (err) {
      logEvent('shutdown_error', { message: (err as Error)?.message ?? null });
    }
    process.exit(0);
  }
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((err) => {
  console.error('[pluggy-mcp] fatal startup error:', err);
  process.exit(1);
});
