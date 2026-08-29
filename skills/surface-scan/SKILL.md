---
name: surface-scan
description: Scan files and payloads for malware using the Surface MCP server. Use when the user asks to check a file for threats, scan code or content for malware, analyze suspicious files, or integrate security scanning into a workflow.
argument-hint: "[file_path or description of what to scan]"
---

# Surface Payload Scanner — MCP Usage Patterns

You have access to the Surface MCP server which provides malware scanning, threat detection, and account management tools. Use these tools to help the user scan files, analyze results, and integrate security into their workflow.

## Available Tools

Surface has two servers and they do **not** expose the same tools. Check which one is
connected before promising the user a capability:

- **Hosted** (`https://app.tendrl.com/surface/mcp`) — the usual setup. 13 tools. It runs
  on Tendrl's side and cannot read your filesystem.
- **Local** (`mcp-server/`, run on your own machine) — adds the tools that need disk
  access or key management.

| Tool | Purpose | Hosted | Local |
|------|---------|:------:|:-----:|
| `scan_payload` | Scan raw text/code/bytes inline — API bodies, agent messages, config snippets, or file contents you have already read | ✅ | ✅ |
| `scan_file` | Scan a file by absolute path — the server opens it itself | — | ✅ |
| `get_scan` | Poll a deferred scan by ID (large inputs return 202 with a scan ID) | ✅ | ✅ |
| `get_scan_history` | Browse past scans (paginated) | ✅ | ✅ |
| `get_scan_detail` | Full result for a historical scan | ✅ | ✅ |
| `list_profiles` | List scan profiles (file type restrictions, engine config, webhooks) | ✅ | ✅ |
| `create_profile` | Create a scan profile | ✅ | ✅ |
| `update_profile` | Update a scan profile | ✅ | ✅ |
| `delete_profile` | Delete a scan profile | ✅ | ✅ |
| `get_usage` | Check scan quota (used vs monthly limit) | ✅ | ✅ |
| `get_account` | Account details and plan info | ✅ | ✅ |
| `get_plans` | List available billing plans | ✅ | ✅ |
| `search_docs` | Search Surface documentation | ✅ | ✅ |
| `list_api_keys` | List Surface API keys (metadata only, never the token) | ✅ | ✅ |
| `create_api_key` | Create a Surface API key | — | ✅ |
| `delete_api_key` | Delete a Surface API key | — | ✅ |

**Scanning a file on the hosted server:** there is no `scan_file` — an MCP tool call
carries JSON, not a file handle, and the hosted server has no access to your disk. Read
the file yourself and pass its contents to `scan_payload`. That is the normal path and
gives the same engines and the same verdict.

## When to Use Each Tool

### Scan a file the user is working on
```
User: "Is this binary safe?" / "Scan this file" / "Check download.exe for malware"
→ Local server:  scan_file with the absolute path
→ Hosted server: read the file, then scan_payload with its contents
```
Do not call `scan_file` without checking it is in the connected server's tool list —
on the hosted server it does not exist.

### Scan code, config, or text content inline
```
User: "Does this payload look malicious?" / "Check this JSON for threats"
→ Use scan_payload with the content and a descriptive label
```
The `label` helps Surface identify content type. Use names like `"request.json"`, `"script.ps1"`, `"agent-message.txt"`.

### Scan multiple files
Call `scan_file` in parallel for each file. Surface handles concurrency. Check `get_usage` first if scanning many files to ensure quota is sufficient.

### Large files (>25MB)
Pass `defer: true` to `scan_file`. This returns a `scanId` immediately. Poll with `get_scan` until the status changes from `"pending"` to a full result.

### Investigate a past scan
Use `get_scan_history` to find it, then `get_scan_detail` for full results.

## Interpreting Scan Results

The scan result includes a `safetyScore` object:

| Field | What it means |
|-------|---------------|
| `score` | 0–100 (100 = safest). Below 30 = malicious. 30–70 = suspicious. Above 70 = clean. |
| `threatLevel` | `"Clean"`, `"Suspicious"`, or `"Malicious"` |
| `confidence` / `confidenceScore` | How certain the verdict is (High/Medium/Low, 0.0–1.0) |
| `primaryThreat` | Main threat name (e.g. `"Trojan.GenericKD"`) |
| `recommendedAction` | `"Allow"`, `"Review"`, or `"Block"` |
| `enginesUsed` | Which engines ran (Malware Signatures, YARA, ML Classifier, Static Analysis, etc.) |
| `cveFindings` | Any CVEs matched — include CVE IDs and descriptions when reporting |

### Other important fields in the full result

- `payloadIOCs` — Extracted indicators (IPs, URLs, domains, hashes found inside the file)
- `archiveEntries` — If the file was a ZIP/TAR/RAR, results for each entry
- `staticAnalysis` — PE/ELF header details, imports, sections
- `behavioral` — MITRE ATT&CK capability mapping
- `promptInjection` — Prompt injection detection (for agentic scanning)
- `sensitiveData` — Credential/key exposure detection
- `toolCallAnalysis` — Dangerous tool call detection (execute, write, HTTP)
- `codeExtraction` — Malicious code pattern detection

## How to Present Results to the User

**Clean files:** Brief confirmation. Mention the safety score and engines used.

**Suspicious files:** Highlight what triggered the suspicion. Show the safety score, primary threat, IOCs, and recommend the user review before trusting the file.

**Malicious files:** Lead with the threat. Show the safety score, threat name, matched signatures/YARA rules, IOCs, CVEs, and recommended action. If the file contains extracted IOCs (malicious IPs, URLs), list them.

Always mention:
1. The safety score and threat level
2. The primary threat (if any)
3. Key IOCs or YARA matches (if any)
4. The recommended action

## Payload Scanning for Agentic Workflows

When the user is building AI agents or processing untrusted input, `scan_payload` is the right tool. It detects:

- **Prompt injection** — Jailbreak attempts, instruction overrides hidden in content
- **Sensitive data exposure** — API keys, credentials, PII in payloads
- **Malicious tool calls** — Dangerous execute/write/HTTP operations
- **Hidden code** — Obfuscated scripts, encoded payloads

Example: Scan an incoming API request body before an agent processes it:
```
scan_payload(payload: <the request body>, label: "api-request.json")
```

## Setup Reference

The Surface MCP server is an HTTP endpoint embedded in the Surface API:

```json
{
  "mcpServers": {
    "surface": {
      "url": "https://your-surface-instance.com/surface/mcp",
      "headers": {
        "Authorization": "Bearer ${SURFACE_SESSION_TOKEN}"
      }
    }
  }
}
```

### Local scanning (optional)

For offline scanning where files never leave your machine, there is a standalone local
MCP server in the `mcp-server/` directory of the Surface repository. Build it and point
your client at the built entry point:

```json
{
  "mcpServers": {
    "surface": {
      "command": "node",
      "args": ["/path/to/surface/mcp-server/dist/index.js"],
      "env": {
        "SURFACE_KEY": "${SURFACE_KEY}",
        "SURFACE_SCANNER_PATH": "/path/to/scanner"
      }
    }
  }
}
```

> **Install by repository, not by name.** Surface's MCP server ships from GitHub,
> not npm: use `npx -y github:tendrl-inc-labs/surface-mcp` (npm builds it from
> source on install). Do not install the npm name `surface-mcp` — that belongs to
> an unrelated third party and would run someone else's code. The local path above
> also works if you have the repo checked out.
