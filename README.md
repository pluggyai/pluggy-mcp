# Pluggy MCP

This is a MCP server for the Pluggy API.

## Installation

Requires Node.js 22.23.4+ or 24.22.1+.

```bash
npm install
```

## Usage in Development (Cursor MCP)

Configure your Cursor MCP server to use this server running in your local machine.

```json
{
  "servers": {
    "pluggy-mcp": {
      "command": "node",
      "args": [
        "{project_root}/dist/index.js"
      ],
      "env": {
        "PLUGGY_CLIENT_ID": "{your_pluggy_client_id}",
        "PLUGGY_CLIENT_SECRET": "{your_pluggy_client_secret}"
      }
    }
  }
}
```

To configure the MCP server in Cursor, go to `Preferences > MCP Servers` and add the server configuration above.

### Developing more Tools

To develop more tools, you can add more tools to the `index.ts` file.

Configure to hotreload the changes using `npm run watch`.


## Releasing

This MCP server is not yet published to the MCP server registry.