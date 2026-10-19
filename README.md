# Surface MCP Server

Model Context Protocol server for [Surface](https://tendrl.com/docs/surface/overview/). Gives any MCP-compatible AI assistant (Claude, etc.) the ability to scan files, manage accounts, and access SDK/API documentation.

## Install

```bash
npx -y github:tendrl-inc-labs/surface-mcp
```

npm clones this repository and builds it from source on install, so there is
nothing to publish and nothing stale to serve.

Install by repository, not by name: an unrelated third party owns the name
`surface-mcp` on npm, and installing that name runs their code.

In an MCP client config:

```json
{
  "mcpServers": {
    "surface": {
      "command": "npx",
      "args": ["-y", "github:tendrl-inc-labs/surface-mcp"],
      "env": {
        "SURFACE_KEY": "${SURFACE_KEY}"
      }
    }
  }
}
```

## Build from source

```bash
git clone https://github.com/tendrl-inc-labs/surface-mcp
cd surface-mcp
npm install
npm run build
```

## Configuration

Set your API key:

```bash
export SURFACE_KEY="your-surface-api-key"
```

### Optional: Local Scanner

Point `SURFACE_SCANNER_PATH` at the Surface scanner binary to scan files locally. Files never leave your machine: the binary runs on your hardware, and this server does not start it with `--report-results`, so apart from the binary's license check nothing about a scan reaches the Surface API.

```bash
export SURFACE_SCANNER_PATH="/usr/local/bin/surface-scanner"
```

When this is not set, `scan_file` uploads to the API instead.

### Optional: Custom API URL

Set a custom base URL (defaults to `https://app.tendrl.com/surface/api`):

```bash
export SURFACE_BASE_URL="http://localhost:8085/api"
```

## Usage with Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "surface": {
      "command": "node",
      "args": ["/path/to/surface/mcp-server/dist/index.js"],
      "env": {
        "SURFACE_KEY": "your-surface-api-key"
      }
    }
  }
}
```

With local scanner (files never leave your machine):

```json
{
  "mcpServers": {
    "surface": {
      "command": "node",
      "args": ["/path/to/surface/mcp-server/dist/index.js"],
      "env": {
        "SURFACE_KEY": "your-surface-api-key",
        "SURFACE_SCANNER_PATH": "/usr/local/bin/surface-scanner"
      }
    }
  }
}
```

The local scanner is part of paid plans and checks its license with your key, so local mode needs `SURFACE_KEY` too (`SURFACE_API_KEY`, the scanner's own name for it, also works). The server hands the key to the scanner in its environment, never on its command line, where other processes on the machine could read it.

## Usage with Claude Code

Add to your Claude Code settings:

```bash
# API mode (uploads to server)
claude mcp add surface node /path/to/surface/mcp-server/dist/index.js -e SURFACE_KEY=your-surface-api-key

# Local scanner mode (files stay on your machine)
claude mcp add surface node /path/to/surface/mcp-server/dist/index.js -e SURFACE_KEY=your-surface-api-key -e SURFACE_SCANNER_PATH=/usr/local/bin/surface-scanner
```

## Tools

| Tool | Description |
|------|-------------|
| `scan_file` | Upload and scan a file for malware (accepts absolute file path) |
| `scan_payload` | Scan raw content for threats — detects prompt injection, SQL/XSS injection, credential leaks, malicious code, and suspicious tool calls. Accepts raw text (default) or base64 for binary. Max 10 MB. |
| `get_scan` | Poll a deferred scan result by scan ID |
| `get_account` | Get account details |
| `get_usage` | Get scan usage vs monthly limit |
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
| API Reference | `surface://docs/api-reference` | Complete REST API documentation |
| SDK Quick Reference | `surface://docs/sdk-overview` | Side-by-side SDK comparison |
| Webhook Guide | `surface://docs/webhooks` | Webhook setup and signature verification |
| Python SDK Docs | `surface://docs/sdk/python` | Python SDK README |
| JavaScript SDK Docs | `surface://docs/sdk/javascript` | JS/TS SDK README |
| Go SDK Docs | `surface://docs/sdk/go` | Go SDK README |
| SDK Source Files | `surface://src/sdk/{lang}/*` | SDK source code (client, models, errors, webhook) |

## Agentic Security

The `scan_payload` tool is designed for AI agent workflows. When an agent scans a payload, Surface automatically detects:

- **Prompt injection** — jailbreak attempts, role hijacking, instruction overrides
- **SQL injection** — union attacks, tautology auth bypass, blind injection
- **XSS injection** — script tags, event handlers, javascript: URIs
- **Credential exposure** — API keys, tokens, private keys, connection strings
- **Malicious code** — reverse shells, download cradles, eval/exec chains
- **Suspicious tool calls** — dangerous execute/write/http operations
- **Known malicious URLs** — checked against threat intelligence feeds

Results include `promptInjection`, `codeExtraction`, `sensitiveData`, and `toolCallAnalysis` fields with detailed findings.

## Prompts

| Prompt | Description |
|--------|-------------|
| `analyze_scan_result` | Analyze a scan result JSON and provide security assessment |
| `generate_sdk_code` | Generate SDK code for a given language and use case |
