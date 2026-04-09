#!/usr/bin/env node

import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";
import { execFile } from "node:child_process";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const DEFAULT_BASE_URL = "https://api.surface.io";

function getBaseUrl(): string {
  return process.env.SURFACE_BASE_URL ?? DEFAULT_BASE_URL;
}

function getApiKey(): string {
  const key = process.env.SURFACE_KEY;
  if (!key) {
    throw new Error(
      "SURFACE_KEY environment variable is required. Set it to your Surface API key.",
    );
  }
  return key;
}

/** Path to a local scanner binary. When set, scan_file shells out instead of calling the API. */
function getScannerPath(): string | undefined {
  return process.env.SURFACE_SCANNER_PATH;
}

// ---------------------------------------------------------------------------
// Local scanner execution
// ---------------------------------------------------------------------------

/**
 * Run the local scanner binary on a file and return parsed JSON output.
 * The binary is invoked with `--format json --api-key <key> <file>`.
 * The API key allows the binary to report results to the server and
 * validate monthly scan quota.
 */
async function localScan(
  scannerPath: string,
  filePath: string,
): Promise<unknown> {
  const apiKey = getApiKey();

  return new Promise((resolve, reject) => {
    const args = ["--format", "json"];

    // Pass API key so the binary can report results and respect server quota
    args.push("--api-key", apiKey);

    args.push(filePath);

    execFile(
      scannerPath,
      args,
      { maxBuffer: 10 * 1024 * 1024, timeout: 120_000 },
      (error, stdout, _stderr) => {
        // The scanner exits 1 for Malicious/Suspicious verdicts — that's
        // expected, not an error. Only reject if there's no parseable output.
        const output = stdout?.trim();
        if (!output) {
          return reject(
            new Error(
              `Scanner produced no output. ${error?.message ?? ""}`.trim(),
            ),
          );
        }

        try {
          resolve(JSON.parse(output));
        } catch {
          reject(new Error(`Failed to parse scanner output: ${output.slice(0, 500)}`));
        }
      },
    );
  });
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function apiRequest(
  method: string,
  endpoint: string,
  body?: unknown,
): Promise<unknown> {
  const url = `${getBaseUrl()}${endpoint}`;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${getApiKey()}`,
  };

  const init: RequestInit = { method, headers };

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  const resp = await fetch(url, init);

  if (!resp.ok) {
    let errorBody: string;
    try {
      errorBody = JSON.stringify(await resp.json());
    } catch {
      errorBody = await resp.text();
    }
    throw new Error(`HTTP ${resp.status}: ${errorBody}`);
  }

  if (resp.status === 204) return null;
  return resp.json();
}

async function apiUpload(
  endpoint: string,
  filePath: string,
  params?: Record<string, string>,
): Promise<unknown> {
  const fileContent = fs.readFileSync(filePath);
  const fileName = path.basename(filePath);

  const formData = new FormData();
  formData.append("file", new Blob([fileContent]), fileName);

  const query = params ? "?" + new URLSearchParams(params).toString() : "";
  const url = `${getBaseUrl()}${endpoint}${query}`;

  const resp = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${getApiKey()}` },
    body: formData,
  });

  if (!resp.ok) {
    let errorBody: string;
    try {
      errorBody = JSON.stringify(await resp.json());
    } catch {
      errorBody = await resp.text();
    }
    throw new Error(`HTTP ${resp.status}: ${errorBody}`);
  }

  return resp.json();
}

// ---------------------------------------------------------------------------
// Resolve project root (for reading SDK/doc files)
// ---------------------------------------------------------------------------

function projectRoot(): string {
  // Walk up from this file's directory to find the repo root
  let dir = path.dirname(new URL(import.meta.url).pathname);
  for (let i = 0; i < 5; i++) {
    if (fs.existsSync(path.join(dir, "backend")) && fs.existsSync(path.join(dir, "sdks"))) {
      return dir;
    }
    dir = path.dirname(dir);
  }
  // Fallback: assume cwd
  return process.cwd();
}

const ROOT = projectRoot();

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "surface",
  version: "1.0.0",
});

// ===========================
// TOOLS — API Operations
// ===========================

// --- Scan File ---
server.tool(
  "scan_file",
  "Scan a file for malware. Returns safety score, threat level, IOCs, YARA matches, and engine results. Accepts an absolute file path. When SURFACE_SCANNER_PATH is set, scans locally using the binary (files never leave your machine). Otherwise uploads to the Surface API.",
  {
    file_path: z.string().describe("Absolute path to the file to scan"),
    defer: z
      .boolean()
      .optional()
      .describe(
        "If true, returns immediately with a scan ID for polling. Use for large files.",
      ),
    request_id: z
      .string()
      .optional()
      .describe("Optional client-generated request ID for idempotency"),
  },
  async ({ file_path: filePath, defer: deferScan, request_id: requestId }) => {
    const scannerPath = getScannerPath();

    // Local scanner mode: shell out to the binary instead of calling the API.
    // Files are scanned locally and never uploaded. The API key is still passed
    // so the binary can report results to the server and respect server quota.
    if (scannerPath) {
      if (deferScan) {
        return {
          content: [
            {
              type: "text",
              text: "Deferred scanning is not supported in local scanner mode. Remove the `defer` option or unset SURFACE_SCANNER_PATH to use the API.",
            },
          ],
        };
      }

      const result = await localScan(scannerPath, filePath);
      return {
        content: [
          { type: "text", text: JSON.stringify(result, null, 2) },
        ],
      };
    }

    // API mode: upload to the remote scanner
    const params: Record<string, string> = {};
    if (deferScan) params.defer = "true";
    if (requestId) params.request_id = requestId;

    const result = await apiUpload("/scan", filePath, params);
    return {
      content: [
        { type: "text", text: JSON.stringify(result, null, 2) },
      ],
    };
  },
);

// --- Scan Payload ---
server.tool(
  "scan_payload",
  "Scan a raw string or payload for malware without file upload. Content type is auto-detected from bytes. Useful for scanning API request/response bodies, form inputs, agent messages, or any text content inline. When SURFACE_SCANNER_PATH is set, scans locally via stdin. Otherwise sends to the Surface API.",
  {
    payload: z
      .string()
      .describe(
        "The content to scan. Can be raw text/code or base64-encoded binary data.",
      ),
    label: z
      .string()
      .optional()
      .describe(
        'Optional label for the payload (e.g. "api-request", "agent-message.json"). Content type is auto-detected.',
      ),
    defer: z
      .boolean()
      .optional()
      .describe("If true, returns immediately with a scan ID for polling."),
  },
  async ({ payload, label, defer: deferScan }) => {
    const scannerPath = getScannerPath();

    // Local scanner mode: pipe via stdin (always raw bytes)
    if (scannerPath) {
      const rawContent = Buffer.from(payload, "utf-8");

      return new Promise((resolve, reject) => {
        const args = [
          "--stdin",
          "--label",
          label ?? "payload.bin",
          "--format",
          "json",
          "--api-key",
          getApiKey(),
        ];

        const child = execFile(
          scannerPath,
          args,
          { maxBuffer: 10 * 1024 * 1024, timeout: 120_000 },
          (error, stdout, _stderr) => {
            const output = stdout?.trim();
            if (!output) {
              return reject(
                new Error(
                  `Scanner produced no output. ${error?.message ?? ""}`.trim(),
                ),
              );
            }
            try {
              const result = JSON.parse(output);
              resolve({
                content: [
                  { type: "text", text: JSON.stringify(result, null, 2) },
                ],
              });
            } catch {
              reject(new Error(`Invalid scanner output: ${output}`));
            }
          },
        );

        // Write payload to stdin
        child.stdin?.write(rawContent);
        child.stdin?.end();
      });
    }

    // API mode: POST JSON to /scan/payload
    const params: Record<string, string> = {};
    if (deferScan) params.defer = "true";

    // Send raw — the API accepts raw text payloads by default (no base64 needed for text)
    const body = JSON.stringify({ payload, label: label || undefined });
    const query = Object.keys(params).length
      ? "?" + new URLSearchParams(params).toString()
      : "";
    const url = `${getBaseUrl()}/scan/payload${query}`;

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${getApiKey()}`,
        "Content-Type": "application/json",
      },
      body,
    });

    if (!resp.ok) {
      let errorBody: string;
      try {
        errorBody = JSON.stringify(await resp.json());
      } catch {
        errorBody = await resp.text();
      }
      throw new Error(`HTTP ${resp.status}: ${errorBody}`);
    }

    const result = await resp.json();
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Get Scan (poll deferred) ---
server.tool(
  "get_scan",
  "Poll the status/result of a deferred scan by scan ID.",
  {
    scan_id: z.string().describe("The scan ID returned from a deferred scan"),
  },
  async ({ scan_id }) => {
    const result = await apiRequest("GET", `/scan/${encodeURIComponent(scan_id)}`);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Get Account ---
server.tool(
  "get_account",
  "Get the current account details including plan, email, and settings.",
  {},
  async () => {
    const result = await apiRequest("GET", "/account");
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Get Usage ---
server.tool(
  "get_usage",
  "Get current scan usage for the account (used vs monthly limit, reset date; response may use legacy credits_* JSON field names).",
  {},
  async () => {
    const result = await apiRequest("GET", "/account/usage");
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- List Scan Profiles ---
server.tool(
  "list_profiles",
  "List all scan profiles for the account. Profiles define allowed file types, size limits, and webhook settings.",
  {},
  async () => {
    const result = await apiRequest("GET", "/account/profiles");
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Create Scan Profile ---
server.tool(
  "create_profile",
  "Create a new scan profile with custom file type restrictions, size limits, and optional webhook.",
  {
    name: z.string().describe("Profile name"),
    allowed_types: z
      .string()
      .optional()
      .describe("Comma-separated allowed file extensions (e.g. 'jpg,png,pdf')"),
    max_file_size: z
      .number()
      .optional()
      .describe("Max file size in bytes"),
    block_malicious_ip: z
      .boolean()
      .optional()
      .describe("Block scans from known malicious IPs"),
    webhook_url: z
      .string()
      .optional()
      .describe("URL to POST scan results to"),
    webhook_api_key: z
      .string()
      .optional()
      .describe("API key sent in webhook requests for authentication"),
  },
  async (params) => {
    const result = await apiRequest("POST", "/account/profiles", params);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Update Scan Profile ---
server.tool(
  "update_profile",
  "Update an existing scan profile.",
  {
    profile_id: z.string().describe("Profile ID to update"),
    name: z.string().optional().describe("New profile name"),
    allowed_types: z.string().optional().describe("New allowed file extensions"),
    max_file_size: z.number().optional().describe("New max file size in bytes"),
    block_malicious_ip: z.boolean().optional(),
    webhook_url: z.string().optional(),
    webhook_api_key: z.string().optional(),
  },
  async ({ profile_id, ...params }) => {
    const result = await apiRequest(
      "PUT",
      `/account/profiles/${encodeURIComponent(profile_id)}`,
      params,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Delete Scan Profile ---
server.tool(
  "delete_profile",
  "Delete a scan profile by ID.",
  {
    profile_id: z.string().describe("Profile ID to delete"),
  },
  async ({ profile_id }) => {
    await apiRequest(
      "DELETE",
      `/account/profiles/${encodeURIComponent(profile_id)}`,
    );
    return {
      content: [{ type: "text", text: "Profile deleted successfully." }],
    };
  },
);

// --- List API Keys ---
server.tool(
  "list_api_keys",
  "List all API keys for the account.",
  {},
  async () => {
    const result = await apiRequest("GET", "/account/keys");
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Create API Key ---
server.tool(
  "create_api_key",
  "Create a new API key. Returns api_key_id (stable identifier, always visible) and token (the Bearer secret — shown once, store it immediately).",
  {
    label: z.string().describe("Human-readable label for the key"),
    profile_id: z
      .string()
      .optional()
      .describe("Scan profile ID to link this key to"),
  },
  async (params) => {
    const result = await apiRequest("POST", "/account/keys", params);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Delete API Key ---
server.tool(
  "delete_api_key",
  "Delete an API key by its internal id (the 'id' field from list_api_keys, not the api_key_id).",
  {
    key_id: z.string().describe("Internal key id to delete (the 'id' field from list_api_keys)"),
  },
  async ({ key_id }) => {
    await apiRequest(
      "DELETE",
      `/account/keys/${encodeURIComponent(key_id)}`,
    );
    return {
      content: [{ type: "text", text: "API key deleted successfully." }],
    };
  },
);

// --- Get Scan History ---
server.tool(
  "get_scan_history",
  "Get paginated scan history for the account.",
  {
    page: z.number().optional().default(1).describe("Page number"),
    limit: z.number().optional().default(25).describe("Results per page"),
  },
  async ({ page, limit }) => {
    const params = new URLSearchParams();
    if (page) params.set("page", String(page));
    if (limit) params.set("limit", String(limit));
    const qs = params.toString();
    const result = await apiRequest("GET", `/account/history${qs ? `?${qs}` : ""}`);
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Get Scan Detail ---
server.tool(
  "get_scan_detail",
  "Get full details of a specific historical scan by its ID.",
  {
    scan_id: z.string().describe("Scan history entry ID"),
  },
  async ({ scan_id }) => {
    const result = await apiRequest(
      "GET",
      `/account/history/${encodeURIComponent(scan_id)}`,
    );
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// --- Get Billing Plans ---
server.tool(
  "get_plans",
  "Get available billing plans and scan limits.",
  {},
  async () => {
    const result = await apiRequest("GET", "/billing/plans");
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  },
);

// ===========================
// RESOURCES — Documentation
// ===========================

// Helper to read a file and return as resource content
function readFileResource(filePath: string): string {
  try {
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return `Error: Could not read file at ${filePath}`;
  }
}

// --- SDK READMEs ---
server.resource(
  "Python SDK Documentation",
  "surface://docs/sdk/python",
  { description: "Python SDK README — installation, usage, async client, batch scanning, error handling" },
  () => ({
    contents: [
      {
        uri: "surface://docs/sdk/python",
        mimeType: "text/markdown",
        text: readFileResource(path.join(ROOT, "sdks/python/README.md")),
      },
    ],
  }),
);

server.resource(
  "JavaScript SDK Documentation",
  "surface://docs/sdk/javascript",
  { description: "JavaScript/TypeScript SDK README — installation, usage, batch scanning, HTTP/2, error handling" },
  () => ({
    contents: [
      {
        uri: "surface://docs/sdk/javascript",
        mimeType: "text/markdown",
        text: readFileResource(path.join(ROOT, "sdks/javascript/README.md")),
      },
    ],
  }),
);

server.resource(
  "Go SDK Documentation",
  "surface://docs/sdk/go",
  { description: "Go SDK README — installation, usage, batch scanning, error handling" },
  () => ({
    contents: [
      {
        uri: "surface://docs/sdk/go",
        mimeType: "text/markdown",
        text: readFileResource(path.join(ROOT, "sdks/go/README.md")),
      },
    ],
  }),
);

// --- SDK Source Code ---
const sdkSources = [
  { name: "Python SDK Client Source", uri: "surface://src/sdk/python/client", file: "sdks/python/surface/client.py" },
  { name: "Python SDK Models Source", uri: "surface://src/sdk/python/models", file: "sdks/python/surface/models.py" },
  { name: "Python SDK Errors Source", uri: "surface://src/sdk/python/errors", file: "sdks/python/surface/errors.py" },
  { name: "JavaScript SDK Client Source", uri: "surface://src/sdk/javascript/client", file: "sdks/javascript/src/client.ts" },
  { name: "JavaScript SDK Models Source", uri: "surface://src/sdk/javascript/models", file: "sdks/javascript/src/models.ts" },
  { name: "JavaScript SDK Errors Source", uri: "surface://src/sdk/javascript/errors", file: "sdks/javascript/src/errors.ts" },
  { name: "JavaScript SDK Webhook Source", uri: "surface://src/sdk/javascript/webhook", file: "sdks/javascript/src/webhook.ts" },
  { name: "Go SDK Source", uri: "surface://src/sdk/go/surface", file: "sdks/go/surface.go" },
  { name: "Go SDK Models Source", uri: "surface://src/sdk/go/models", file: "sdks/go/models.go" },
  { name: "Go SDK Errors Source", uri: "surface://src/sdk/go/errors", file: "sdks/go/errors.go" },
  { name: "Go SDK Webhook Source", uri: "surface://src/sdk/go/webhook", file: "sdks/go/webhook.go" },
];

for (const src of sdkSources) {
  const mime = src.file.endsWith(".py")
    ? "text/x-python"
    : src.file.endsWith(".go")
      ? "text/x-go"
      : "text/typescript";

  server.resource(src.name, src.uri, { description: `Source code: ${src.file}` }, () => ({
    contents: [
      {
        uri: src.uri,
        mimeType: mime,
        text: readFileResource(path.join(ROOT, src.file)),
      },
    ],
  }));
}

// --- API Reference (comprehensive markdown) ---
const apiReference = `# Surface API Reference

Base URL: \`https://api.surface.io\`

All authenticated endpoints require \`Authorization: Bearer <api_key>\` header.

---

## Scanning

### POST /scan
Upload and scan a file for malware.

**Auth:** Required (API key)
**Content-Type:** multipart/form-data

**Form fields:**
- \`file\` (required) — The file to scan

**Query parameters:**
- \`defer=true\` — Return immediately with a scan ID (HTTP 202) instead of waiting for results
- \`request_id=<string>\` — Client-generated ID for idempotency

**Response (200 — synchronous scan):**
\`\`\`json
{
  "requestId": "uuid",
  "name": "malware.exe",
  "size": 102400,
  "hash": "sha256:...",
  "contentType": "application/x-executable",
  "safetyScore": {
    "score": 15,
    "threatLevel": "Malicious",
    "confidence": "High",
    "confidenceScore": 0.92,
    "confidenceReason": "5 engines analyzed, known malware signature matched",
    "primaryThreat": "Trojan.GenericKD",
    "threatSummary": "Known malware signature matched",
    "enginesUsed": ["Malware Signatures", "YARA", "StaticAnalysis", "TLSH", "Capa"],
    "recommendedAction": "Block",
    "cveFindings": []
  },
  "scanTimeMs": 1234,
  "timestamp": 1700000000,
  "payloadIOCs": [{"items": ["192.168.1.1"], "type": "ip"}],
  "archiveEntries": [],
  "oletoolsResult": null,
  "staticAnalysis": {}
}
\`\`\`

**Response (202 — deferred scan):**
\`\`\`json
{
  "scanId": "uuid",
  "requestId": "uuid",
  "status": "pending",
  "message": "Scan queued"
}
\`\`\`

**Errors:** 400 (validation), 401 (auth), 429 (rate limit or quota exceeded)

### GET /scan/:id
Poll the result of a deferred scan.

**Auth:** Required

---

## Account

### GET /account
Get account details (email, plan, settings, scan counts).

### GET /account/usage
Scan usage vs monthly allowance. Field names may still use \`credits_*\` / \`monthly_credits\` for API compatibility.
\`\`\`json
{
  "credits_used": 45,
  "monthly_credits": 500,
  "credits_remaining": 455,
  "credits_reset_at": "2026-04-01T00:00:00Z"
}
\`\`\`

### PUT /account/settings
Update account settings (allowed_types, max_file_size, block_malicious_ip, display_name).

### PUT /account/password
Change password. Body: \`{"current_password": "...", "new_password": "..."}\`

---

## Scan History

### GET /account/history?page=1&limit=25
Paginated scan history.

### GET /account/history/:id
Full scan detail for a history entry.

### GET /account/history/:id/export
Export a scan result as JSON.

---

## Scan Profiles

Profiles define file type restrictions, size limits, and webhook configuration.

### GET /account/profiles
List all profiles.

### POST /account/profiles
Create a profile.
\`\`\`json
{
  "name": "Images Only",
  "allowed_types": "jpg,jpeg,png,gif,webp",
  "max_file_size": 10485760,
  "block_malicious_ip": true,
  "webhook_url": "https://example.com/webhook",
  "webhook_api_key": "secret"
}
\`\`\`

### GET /account/profiles/:id
Get a single profile.

### PUT /account/profiles/:id
Update a profile (partial update supported).

### DELETE /account/profiles/:id
Delete a profile.

### POST /account/profiles/:id/test-webhook
Send a test webhook payload to the profile's configured URL.

---

## API Keys

Each key has two fields:
- \`api_key_id\` — stable UUID, always visible, used to identify the key
- \`token\` — the Bearer secret (returned once at creation, never retrievable again)

Use \`Authorization: Bearer <token>\` to authenticate requests.

### GET /account/keys
List all API keys. Returns \`api_key_id\`, \`role_name\`, \`label\`, \`profile_id\`, timestamps — never the token.

### POST /account/keys
Create a key. Body: \`{"label": "Production", "role_name": "scanner", "profile_id": "uuid"}\`
Response includes \`api_key_id\` and \`token\` (shown once — store it immediately).

### PATCH /account/keys/:id/profile
Assign or unassign a scan profile. Body: \`{"profile_id": "uuid"}\` (empty string to unassign).

### DELETE /account/keys/:id
Revoke a key by its internal \`id\` (not \`api_key_id\`).

---

## Billing

### GET /billing/plans
Get available plans and scan limits (public endpoint, no auth required).

---

## Blocked IPs

### GET /account/blocked-ips
List IPs blocked by malicious IP detection.

### DELETE /account/blocked-ips/:ip
Unblock an IP.

---

## Webhooks

When a scan profile has a \`webhook_url\` configured, Surface POSTs the scan result to that URL after every scan.

**Headers sent:**
- \`Content-Type: application/json\`
- \`X-Surface-Signature: sha256=<hmac>\` — HMAC-SHA256 of the body using \`webhook_api_key\` as the secret
- \`X-API-Key: <webhook_api_key>\`

**Payload:**
\`\`\`json
{
  "requestId": "uuid",
  "file": { "name": "test.exe", "size": 1024, "hash": "sha256:...", "contentType": "..." },
  "scanResult": { ... },
  "isMalicious": false,
  "isSuspicious": false
}
\`\`\`

**Signature verification:** Compute \`HMAC-SHA256(body_bytes, webhook_api_key)\` and compare with the signature header. All SDKs provide a \`verify_webhook_signature\` helper.

---

## Error Responses

All errors return JSON: \`{"error": "message", "requestId": "uuid"}\`

| Status | Error Type | Description |
|--------|-----------|-------------|
| 400 | ValidationError | Invalid request parameters |
| 401 | AuthenticationError | Invalid or missing API key |
| 404 | NotFoundError | Resource not found |
| 429 | RateLimitError | Too many requests (has Retry-After header) |
| 429 | QuotaExceededError | Monthly scan quota exhausted |

---

## Safety Score

Every scan returns a \`safetyScore\` object:

| Field | Type | Description |
|-------|------|-------------|
| score | int | 0-100 safety score (100 = safest) |
| threatLevel | string | "Clean", "Suspicious", or "Malicious" |
| confidence | string | "High", "Medium", or "Low" |
| confidenceScore | float | 0.0-1.0 numeric confidence |
| primaryThreat | string | Main threat identified |
| threatSummary | string | Human-readable summary |
| enginesUsed | string[] | Engines that analyzed the file |
| recommendedAction | string | "Allow", "Review", or "Block" |
| cveFindings | CVEInfo[] | Any CVEs matched by YARA rules |

## Scan Engines

Surface uses multiple analysis engines:
- **Malware Signatures** — Hash-based known-malware detection
- **YARA** — Rule-based pattern matching with auto-updating rules
- **Static Analysis** — PE header analysis, import table inspection
- **TLSH** — Fuzzy hash similarity matching against known malware
- **Capa** — Capability detection (ATT&CK mapping)
- **ML Classifier** — Machine learning PE classification
- **FLOSS** — String deobfuscation
- **OLEtools** — Office document macro analysis
- **Box-JS** — JavaScript deobfuscation and analysis
- **Detect It Easy (DiE)** — Packer/compiler detection
- **PDF Analysis** — PDF structure and stream analysis
`;

server.resource(
  "API Reference",
  "surface://docs/api-reference",
  { description: "Complete Surface REST API reference — all endpoints, request/response formats, error codes, safety score fields, and scan engines" },
  () => ({
    contents: [
      {
        uri: "surface://docs/api-reference",
        mimeType: "text/markdown",
        text: apiReference,
      },
    ],
  }),
);

// --- Webhook Guide ---
const webhookGuide = `# Surface Webhook Integration Guide

## Overview

Webhooks let your server react to scan results in real-time. When a scan profile has a webhook URL configured, Surface POSTs the full scan result to your endpoint immediately after analysis completes.

## Setup

1. Create or update a scan profile with a webhook URL:
   \`\`\`
   POST /account/profiles
   {
     "name": "With Webhook",
     "webhook_url": "https://your-app.com/webhooks/surface",
     "webhook_api_key": "your-secret-key"
   }
   \`\`\`

2. Create an API key linked to that profile:
   \`\`\`
   POST /account/keys
   { "label": "Webhook Key", "profile_id": "<profile-id>" }
   \`\`\`

3. Use that API key for scans — results will be POSTed to your webhook URL.

## Webhook Payload

\`\`\`json
{
  "requestId": "uuid",
  "file": {
    "name": "document.pdf",
    "size": 204800,
    "hash": "sha256:abc123...",
    "contentType": "application/pdf"
  },
  "scanResult": {
    "safetyScore": {
      "score": 95,
      "threatLevel": "Clean",
      "recommendedAction": "Allow",
      ...
    },
    ...
  },
  "isMalicious": false,
  "isSuspicious": false
}
\`\`\`

## Signature Verification

Every webhook request includes an \`X-Surface-Signature\` header containing an HMAC-SHA256 signature of the request body.

### Python
\`\`\`python
from surface import verify_webhook_signature

is_valid = verify_webhook_signature(
    body=request.body,
    secret="your_webhook_secret",
    signature_header=request.headers["X-Surface-Signature"],
)
\`\`\`

### JavaScript
\`\`\`typescript
import { verifyWebhookSignature } from "@surface/sdk";

const isValid = await verifyWebhookSignature(
    requestBody,
    "your_webhook_secret",
    request.headers["x-surface-signature"],
);
\`\`\`

### Go
\`\`\`go
isValid := surface.VerifyWebhookSignature(
    bodyBytes,
    "your_webhook_secret",
    r.Header.Get("X-Surface-Signature"),
)
\`\`\`

## Testing

Use the test webhook endpoint to send a sample payload:
\`\`\`
POST /account/profiles/:id/test-webhook
\`\`\`

## Best Practices

- Always verify the signature before processing
- Respond with 2xx within 10 seconds (scan delivery will retry on failure)
- Use the \`requestId\` to correlate webhooks with your original scan requests
- Store the raw payload for audit trails
`;

server.resource(
  "Webhook Integration Guide",
  "surface://docs/webhooks",
  { description: "Guide for setting up Surface webhook integrations — payload format, signature verification, and best practices" },
  () => ({
    contents: [
      {
        uri: "surface://docs/webhooks",
        mimeType: "text/markdown",
        text: webhookGuide,
      },
    ],
  }),
);

// --- SDK Quick Reference (comparison) ---
const sdkQuickRef = `# Surface SDK Quick Reference

## Installation

| Language | Install |
|----------|---------|
| Python | \`pip install surface\` |
| JavaScript | \`npm install @surface/sdk\` |
| Go | \`go get github.com/tendrl-inc-labs/surface-go\` |

## Authentication

All SDKs check for an API key in this order:
1. Constructor parameter (\`api_key\` / \`apiKey\`)
2. \`SURFACE_KEY\` environment variable

If neither is set, an \`AuthenticationError\` is raised/thrown at construction time.

## Sync vs Async

| SDK | Sync | Async | Batch Scanning |
|-----|------|-------|----------------|
| Python | \`SurfaceClient\` | \`AsyncSurfaceClient\` | \`async_client.scan_files([...])\` |
| JavaScript | — | All methods are async (Promise) | \`client.scanFiles([...])\` |
| Go | All methods are sync (blocking) | Use goroutines | \`client.ScanFiles(ctx, paths, opts, concurrency)\` |

## Scan File — All SDKs

### Python
\`\`\`python
# Sync
client = SurfaceClient()
result = client.scan_file("malware.exe")
result = client.scan_file(file_bytes)
result = client.scan_file(open("f.bin", "rb"))

# Async
async with AsyncSurfaceClient(max_concurrency=5) as client:
    results = await client.scan_files(["a.exe", "b.pdf", "c.zip"])
\`\`\`

### JavaScript
\`\`\`typescript
const client = new SurfaceClient();
const result = await client.scanFile(file);       // File, Blob, Buffer, ReadableStream
const results = await client.scanFiles(files, { maxConcurrency: 5 });
\`\`\`

### Go
\`\`\`go
client, _ := surface.NewClient("")
result, _ := client.ScanFile(ctx, "malware.exe", nil)
result, _ := client.ScanBytes(ctx, "sample.bin", data, nil)
result, _ := client.ScanReader(ctx, "upload.zip", reader, nil)
results, _ := client.ScanFiles(ctx, paths, nil, 5)
\`\`\`

## Error Types (same across all SDKs)

| Error | HTTP Status | Description |
|-------|-------------|-------------|
| AuthenticationError | 401 | Invalid or missing API key |
| ValidationError | 400 | Invalid request |
| NotFoundError | 404 | Resource not found |
| RateLimitError | 429 | Too many requests |
| QuotaExceededError | 429 | Monthly scan quota exhausted |
| SurfaceError | * | Base error class |

## HTTP/2

| SDK | HTTP/2 Support |
|-----|---------------|
| Python | Enabled by default (\`httpx[http2]\`) |
| JavaScript | Automatic in browsers; pass custom \`fetch\` (undici) for Node.js |
| Go | Automatic over TLS via \`net/http\` ALPN |
`;

server.resource(
  "SDK Quick Reference",
  "surface://docs/sdk-overview",
  { description: "Side-by-side comparison of Python, JavaScript, and Go SDKs — installation, auth, sync/async, batch scanning, error handling" },
  () => ({
    contents: [
      {
        uri: "surface://docs/sdk-overview",
        mimeType: "text/markdown",
        text: sdkQuickRef,
      },
    ],
  }),
);

// --- Dynamic resource: SDK docs by language ---
server.resource(
  "SDK README by Language",
  new ResourceTemplate("surface://docs/sdk/{language}", { list: undefined }),
  { description: "SDK documentation for a specific language (python, javascript, go)" },
  (uri, { language }) => {
    const lang = String(language);
    const readmePath = path.join(ROOT, `sdks/${lang}/README.md`);
    return {
      contents: [
        {
          uri: uri.href,
          mimeType: "text/markdown",
          text: readFileResource(readmePath),
        },
      ],
    };
  },
);

// ===========================
// PROMPTS
// ===========================

server.prompt(
  "analyze_scan_result",
  "Analyze a Surface scan result and provide a security assessment with recommended actions.",
  { scan_json: z.string().describe("The JSON scan result to analyze") },
  ({ scan_json }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Analyze this Surface scan result and provide:
1. A plain-English summary of the findings
2. The risk level and why
3. Recommended actions (block, quarantine, allow, investigate further)
4. Any notable IOCs, YARA matches, or engine detections worth highlighting

Scan result:
\`\`\`json
${scan_json}
\`\`\``,
        },
      },
    ],
  }),
);

server.prompt(
  "generate_sdk_code",
  "Generate code using a Surface SDK for a given use case.",
  {
    language: z.enum(["python", "javascript", "go"]).describe("SDK language"),
    use_case: z.string().describe("What the code should do (e.g. 'scan all PDFs in a directory', 'set up webhook handler')"),
  },
  ({ language, use_case }) => ({
    messages: [
      {
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `Generate ${language} code using the Surface ${language} SDK for the following use case:

${use_case}

Use the official SDK patterns (proper imports, error handling, auth via SURFACE_KEY env var). Include brief comments explaining each step. Make the code production-ready.`,
        },
      },
    ],
  }),
);

// ===========================
// Start server
// ===========================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
