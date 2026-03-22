# SrcFile MCP Server

Model Context Protocol server for [SrcFile](https://srcfile.io). Gives any MCP-compatible AI assistant (Claude, etc.) the ability to scan files, manage accounts, and access SDK/API documentation.

## Setup

```bash
cd mcp-server
npm install
npm run build
```

## Configuration

Set your API key:

```bash
export SRCFILE_KEY="sfk_xxx.secret"
```

### Optional: Local Scanner

Point `SRCFILE_SCANNER_PATH` at the SrcFile scanner binary to scan files locally. Files never leave your machine — the binary runs on your hardware and reports results to the server.

```bash
export SRCFILE_SCANNER_PATH="/usr/local/bin/srcfile-scanner"
```

When this is not set, `scan_file` uploads to the API instead.

### Optional: Custom API URL

Set a custom base URL (defaults to `https://api.srcfile.io`). For a local deployment of the open-source backend, include the `/api` path:

```bash
export SRCFILE_BASE_URL="http://localhost:8080/api"
```

## Usage with Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "srcfile": {
      "command": "node",
      "args": ["/path/to/srcfile/mcp-server/dist/index.js"],
      "env": {
        "SRCFILE_KEY": "sfk_xxx.secret"
      }
    }
  }
}
```

With local scanner (files never leave your machine):

```json
{
  "mcpServers": {
    "srcfile": {
      "command": "node",
      "args": ["/path/to/srcfile/mcp-server/dist/index.js"],
      "env": {
        "SRCFILE_KEY": "sfk_xxx.secret",
        "SRCFILE_SCANNER_PATH": "/usr/local/bin/srcfile-scanner"
      }
    }
  }
}
```

## Usage with Claude Code

Add to your Claude Code settings:

```bash
# API mode (uploads to server)
claude mcp add srcfile node /path/to/srcfile/mcp-server/dist/index.js -e SRCFILE_KEY=sfk_xxx.secret

# Local scanner mode (files stay on your machine)
claude mcp add srcfile node /path/to/srcfile/mcp-server/dist/index.js -e SRCFILE_KEY=sfk_xxx.secret -e SRCFILE_SCANNER_PATH=/usr/local/bin/srcfile-scanner
```

## Tools

| Tool | Description |
|------|-------------|
| `scan_file` | Upload and scan a file for malware (accepts absolute file path) |
| `scan_payload` | Scan raw content by payload (`payload`, `label`, `encoding`, `defer` params; raw text default, base64 for binary; max 10 MB) |
| `get_scan` | Poll a deferred scan result by scan ID |
| `get_account` | Get account details |
| `get_usage` | Get credit usage |
| `list_profiles` | List scan profiles |
| `create_profile` | Create a scan profile |
| `update_profile` | Update a scan profile |
| `delete_profile` | Delete a scan profile |
| `list_api_keys` | List API keys |
| `create_api_key` | Create an API key |
| `delete_api_key` | Delete an API key |
| `get_scan_history` | Get paginated scan history |
| `get_scan_detail` | Get full details of a historical scan |
| `get_plans` | Get available billing plans |

## Resources

| Resource | URI | Description |
|----------|-----|-------------|
| API Reference | `srcfile://docs/api-reference` | Complete REST API documentation |
| SDK Quick Reference | `srcfile://docs/sdk-overview` | Side-by-side SDK comparison |
| Webhook Guide | `srcfile://docs/webhooks` | Webhook setup and signature verification |
| Python SDK Docs | `srcfile://docs/sdk/python` | Python SDK README |
| JavaScript SDK Docs | `srcfile://docs/sdk/javascript` | JS/TS SDK README |
| Go SDK Docs | `srcfile://docs/sdk/go` | Go SDK README |
| SDK Source Files | `srcfile://src/sdk/{lang}/*` | SDK source code (client, models, errors, webhook) |

## Prompts

| Prompt | Description |
|--------|-------------|
| `analyze_scan_result` | Analyze a scan result JSON and provide security assessment |
| `generate_sdk_code` | Generate SDK code for a given language and use case |
