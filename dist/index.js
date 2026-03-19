#!/usr/bin/env node
import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";
// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const DEFAULT_BASE_URL = "https://api.srcfile.io";
function getBaseUrl() {
    return process.env.SRCFILE_BASE_URL ?? DEFAULT_BASE_URL;
}
function getApiKey() {
    const key = process.env.SRCFILE_KEY;
    if (!key) {
        throw new Error("SRCFILE_KEY environment variable is required. Set it to your SrcFile API key.");
    }
    return key;
}
// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------
async function apiRequest(method, endpoint, body) {
    const url = `${getBaseUrl()}${endpoint}`;
    const headers = {
        Authorization: `Bearer ${getApiKey()}`,
    };
    const init = { method, headers };
    if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
    }
    const resp = await fetch(url, init);
    if (!resp.ok) {
        let errorBody;
        try {
            errorBody = JSON.stringify(await resp.json());
        }
        catch {
            errorBody = await resp.text();
        }
        throw new Error(`HTTP ${resp.status}: ${errorBody}`);
    }
    if (resp.status === 204)
        return null;
    return resp.json();
}
async function apiUpload(endpoint, filePath, params) {
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
        let errorBody;
        try {
            errorBody = JSON.stringify(await resp.json());
        }
        catch {
            errorBody = await resp.text();
        }
        throw new Error(`HTTP ${resp.status}: ${errorBody}`);
    }
    return resp.json();
}
// ---------------------------------------------------------------------------
// Resolve project root (for reading SDK/doc files)
// ---------------------------------------------------------------------------
function projectRoot() {
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
    name: "srcfile",
    version: "1.0.0",
});
// ===========================
// TOOLS — API Operations
// ===========================
// --- Scan File ---
server.tool("scan_file", "Upload and scan a file for malware. Returns safety score, threat level, IOCs, YARA matches, and engine results. Accepts an absolute file path.", {
    file_path: z.string().describe("Absolute path to the file to scan"),
    defer: z
        .boolean()
        .optional()
        .describe("If true, returns immediately with a scan ID for polling. Use for large files."),
    request_id: z
        .string()
        .optional()
        .describe("Optional client-generated request ID for idempotency"),
}, async ({ file_path: filePath, defer: deferScan, request_id: requestId }) => {
    const params = {};
    if (deferScan)
        params.defer = "true";
    if (requestId)
        params.request_id = requestId;
    const result = await apiUpload("/scan", filePath, params);
    return {
        content: [
            { type: "text", text: JSON.stringify(result, null, 2) },
        ],
    };
});
// --- Get Scan (poll deferred) ---
server.tool("get_scan", "Poll the status/result of a deferred scan by scan ID.", {
    scan_id: z.string().describe("The scan ID returned from a deferred scan"),
}, async ({ scan_id }) => {
    const result = await apiRequest("GET", `/scan/${encodeURIComponent(scan_id)}`);
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- Get Account ---
server.tool("get_account", "Get the current account details including plan, email, and settings.", {}, async () => {
    const result = await apiRequest("GET", "/account");
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- Get Usage ---
server.tool("get_usage", "Get current credit usage for the account (credits used, monthly limit, reset date).", {}, async () => {
    const result = await apiRequest("GET", "/account/usage");
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- List Scan Profiles ---
server.tool("list_profiles", "List all scan profiles for the account. Profiles define allowed file types, size limits, and webhook settings.", {}, async () => {
    const result = await apiRequest("GET", "/account/profiles");
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- Create Scan Profile ---
server.tool("create_profile", "Create a new scan profile with custom file type restrictions, size limits, and optional webhook.", {
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
}, async (params) => {
    const result = await apiRequest("POST", "/account/profiles", params);
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- Update Scan Profile ---
server.tool("update_profile", "Update an existing scan profile.", {
    profile_id: z.string().describe("Profile ID to update"),
    name: z.string().optional().describe("New profile name"),
    allowed_types: z.string().optional().describe("New allowed file extensions"),
    max_file_size: z.number().optional().describe("New max file size in bytes"),
    block_malicious_ip: z.boolean().optional(),
    webhook_url: z.string().optional(),
    webhook_api_key: z.string().optional(),
}, async ({ profile_id, ...params }) => {
    const result = await apiRequest("PUT", `/account/profiles/${encodeURIComponent(profile_id)}`, params);
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- Delete Scan Profile ---
server.tool("delete_profile", "Delete a scan profile by ID.", {
    profile_id: z.string().describe("Profile ID to delete"),
}, async ({ profile_id }) => {
    await apiRequest("DELETE", `/account/profiles/${encodeURIComponent(profile_id)}`);
    return {
        content: [{ type: "text", text: "Profile deleted successfully." }],
    };
});
// --- List API Keys ---
server.tool("list_api_keys", "List all API keys for the account.", {}, async () => {
    const result = await apiRequest("GET", "/account/keys");
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- Create API Key ---
server.tool("create_api_key", "Create a new API key, optionally linked to a scan profile.", {
    label: z.string().describe("Human-readable label for the key"),
    profile_id: z
        .string()
        .optional()
        .describe("Scan profile ID to link this key to"),
}, async (params) => {
    const result = await apiRequest("POST", "/account/keys", params);
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- Delete API Key ---
server.tool("delete_api_key", "Delete an API key by ID.", {
    key_id: z.string().describe("API key ID to delete"),
}, async ({ key_id }) => {
    await apiRequest("DELETE", `/account/keys/${encodeURIComponent(key_id)}`);
    return {
        content: [{ type: "text", text: "API key deleted successfully." }],
    };
});
// --- Get Scan History ---
server.tool("get_scan_history", "Get paginated scan history for the account.", {
    page: z.number().optional().default(1).describe("Page number"),
    limit: z.number().optional().default(25).describe("Results per page"),
}, async ({ page, limit }) => {
    const params = new URLSearchParams();
    if (page)
        params.set("page", String(page));
    if (limit)
        params.set("limit", String(limit));
    const qs = params.toString();
    const result = await apiRequest("GET", `/account/history${qs ? `?${qs}` : ""}`);
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- Get Scan Detail ---
server.tool("get_scan_detail", "Get full details of a specific historical scan by its ID.", {
    scan_id: z.string().describe("Scan history entry ID"),
}, async ({ scan_id }) => {
    const result = await apiRequest("GET", `/account/history/${encodeURIComponent(scan_id)}`);
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// --- Get Billing Plans ---
server.tool("get_plans", "Get available billing plans and credit tiers.", {}, async () => {
    const result = await apiRequest("GET", "/billing/plans");
    return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
});
// ===========================
// RESOURCES — Documentation
// ===========================
// Helper to read a file and return as resource content
function readFileResource(filePath) {
    try {
        return fs.readFileSync(filePath, "utf-8");
    }
    catch {
        return `Error: Could not read file at ${filePath}`;
    }
}
// --- SDK READMEs ---
server.resource("Python SDK Documentation", "srcfile://docs/sdk/python", { description: "Python SDK README — installation, usage, async client, batch scanning, error handling" }, () => ({
    contents: [
        {
            uri: "srcfile://docs/sdk/python",
            mimeType: "text/markdown",
            text: readFileResource(path.join(ROOT, "sdks/python/README.md")),
        },
    ],
}));
server.resource("JavaScript SDK Documentation", "srcfile://docs/sdk/javascript", { description: "JavaScript/TypeScript SDK README — installation, usage, batch scanning, HTTP/2, error handling" }, () => ({
    contents: [
        {
            uri: "srcfile://docs/sdk/javascript",
            mimeType: "text/markdown",
            text: readFileResource(path.join(ROOT, "sdks/javascript/README.md")),
        },
    ],
}));
server.resource("Go SDK Documentation", "srcfile://docs/sdk/go", { description: "Go SDK README — installation, usage, batch scanning, error handling" }, () => ({
    contents: [
        {
            uri: "srcfile://docs/sdk/go",
            mimeType: "text/markdown",
            text: readFileResource(path.join(ROOT, "sdks/go/README.md")),
        },
    ],
}));
// --- SDK Source Code ---
const sdkSources = [
    { name: "Python SDK Client Source", uri: "srcfile://src/sdk/python/client", file: "sdks/python/srcfile/client.py" },
    { name: "Python SDK Models Source", uri: "srcfile://src/sdk/python/models", file: "sdks/python/srcfile/models.py" },
    { name: "Python SDK Errors Source", uri: "srcfile://src/sdk/python/errors", file: "sdks/python/srcfile/errors.py" },
    { name: "JavaScript SDK Client Source", uri: "srcfile://src/sdk/javascript/client", file: "sdks/javascript/src/client.ts" },
    { name: "JavaScript SDK Models Source", uri: "srcfile://src/sdk/javascript/models", file: "sdks/javascript/src/models.ts" },
    { name: "JavaScript SDK Errors Source", uri: "srcfile://src/sdk/javascript/errors", file: "sdks/javascript/src/errors.ts" },
    { name: "JavaScript SDK Webhook Source", uri: "srcfile://src/sdk/javascript/webhook", file: "sdks/javascript/src/webhook.ts" },
    { name: "Go SDK Source", uri: "srcfile://src/sdk/go/srcfile", file: "sdks/go/srcfile.go" },
    { name: "Go SDK Models Source", uri: "srcfile://src/sdk/go/models", file: "sdks/go/models.go" },
    { name: "Go SDK Errors Source", uri: "srcfile://src/sdk/go/errors", file: "sdks/go/errors.go" },
    { name: "Go SDK Webhook Source", uri: "srcfile://src/sdk/go/webhook", file: "sdks/go/webhook.go" },
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
const apiReference = `# SrcFile API Reference

Base URL: \`https://api.srcfile.io\`

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
Get credit usage.
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

Keys are linked to scan profiles and inherit their settings.

### GET /account/keys
List all API keys.

### POST /account/keys
Create a key. Body: \`{"label": "Production", "profile_id": "uuid"}\`

### PUT /account/keys/:id
Update a key.

### DELETE /account/keys/:id
Delete a key.

---

## Billing

### GET /billing/plans
Get available plans and credit tiers (public endpoint, no auth required).

---

## Blocked IPs

### GET /account/blocked-ips
List IPs blocked by malicious IP detection.

### DELETE /account/blocked-ips/:ip
Unblock an IP.

---

## Webhooks

When a scan profile has a \`webhook_url\` configured, SrcFile POSTs the scan result to that URL after every scan.

**Headers sent:**
- \`Content-Type: application/json\`
- \`X-SrcFile-Signature: sha256=<hmac>\` — HMAC-SHA256 of the body using \`webhook_api_key\` as the secret
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
| 429 | QuotaExceededError | Monthly credit quota exhausted |

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

SrcFile uses multiple analysis engines:
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
server.resource("API Reference", "srcfile://docs/api-reference", { description: "Complete SrcFile REST API reference — all endpoints, request/response formats, error codes, safety score fields, and scan engines" }, () => ({
    contents: [
        {
            uri: "srcfile://docs/api-reference",
            mimeType: "text/markdown",
            text: apiReference,
        },
    ],
}));
// --- Webhook Guide ---
const webhookGuide = `# SrcFile Webhook Integration Guide

## Overview

Webhooks let your server react to scan results in real-time. When a scan profile has a webhook URL configured, SrcFile POSTs the full scan result to your endpoint immediately after analysis completes.

## Setup

1. Create or update a scan profile with a webhook URL:
   \`\`\`
   POST /account/profiles
   {
     "name": "With Webhook",
     "webhook_url": "https://your-app.com/webhooks/srcfile",
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

Every webhook request includes an \`X-SrcFile-Signature\` header containing an HMAC-SHA256 signature of the request body.

### Python
\`\`\`python
from srcfile import verify_webhook_signature

is_valid = verify_webhook_signature(
    body=request.body,
    secret="your_webhook_secret",
    signature_header=request.headers["X-SrcFile-Signature"],
)
\`\`\`

### JavaScript
\`\`\`typescript
import { verifyWebhookSignature } from "@srcfile/sdk";

const isValid = await verifyWebhookSignature(
    requestBody,
    "your_webhook_secret",
    request.headers["x-srcfile-signature"],
);
\`\`\`

### Go
\`\`\`go
isValid := srcfile.VerifyWebhookSignature(
    bodyBytes,
    "your_webhook_secret",
    r.Header.Get("X-SrcFile-Signature"),
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
server.resource("Webhook Integration Guide", "srcfile://docs/webhooks", { description: "Guide for setting up SrcFile webhook integrations — payload format, signature verification, and best practices" }, () => ({
    contents: [
        {
            uri: "srcfile://docs/webhooks",
            mimeType: "text/markdown",
            text: webhookGuide,
        },
    ],
}));
// --- SDK Quick Reference (comparison) ---
const sdkQuickRef = `# SrcFile SDK Quick Reference

## Installation

| Language | Install |
|----------|---------|
| Python | \`pip install srcfile\` |
| JavaScript | \`npm install @srcfile/sdk\` |
| Go | \`go get github.com/tendrl-inc-labs/srcfile-go\` |

## Authentication

All SDKs check for an API key in this order:
1. Constructor parameter (\`api_key\` / \`apiKey\`)
2. \`SRCFILE_KEY\` environment variable

If neither is set, an \`AuthenticationError\` is raised/thrown at construction time.

## Sync vs Async

| SDK | Sync | Async | Batch Scanning |
|-----|------|-------|----------------|
| Python | \`SrcFileClient\` | \`AsyncSrcFileClient\` | \`async_client.scan_files([...])\` |
| JavaScript | — | All methods are async (Promise) | \`client.scanFiles([...])\` |
| Go | All methods are sync (blocking) | Use goroutines | \`client.ScanFiles(ctx, paths, opts, concurrency)\` |

## Scan File — All SDKs

### Python
\`\`\`python
# Sync
client = SrcFileClient()
result = client.scan_file("malware.exe")
result = client.scan_file(file_bytes)
result = client.scan_file(open("f.bin", "rb"))

# Async
async with AsyncSrcFileClient(max_concurrency=5) as client:
    results = await client.scan_files(["a.exe", "b.pdf", "c.zip"])
\`\`\`

### JavaScript
\`\`\`typescript
const client = new SrcFileClient();
const result = await client.scanFile(file);       // File, Blob, Buffer, ReadableStream
const results = await client.scanFiles(files, { maxConcurrency: 5 });
\`\`\`

### Go
\`\`\`go
client, _ := srcfile.NewClient("")
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
| QuotaExceededError | 429 | Monthly credits exhausted |
| SrcFileError | * | Base error class |

## HTTP/2

| SDK | HTTP/2 Support |
|-----|---------------|
| Python | Enabled by default (\`httpx[http2]\`) |
| JavaScript | Automatic in browsers; pass custom \`fetch\` (undici) for Node.js |
| Go | Automatic over TLS via \`net/http\` ALPN |
`;
server.resource("SDK Quick Reference", "srcfile://docs/sdk-overview", { description: "Side-by-side comparison of Python, JavaScript, and Go SDKs — installation, auth, sync/async, batch scanning, error handling" }, () => ({
    contents: [
        {
            uri: "srcfile://docs/sdk-overview",
            mimeType: "text/markdown",
            text: sdkQuickRef,
        },
    ],
}));
// --- Dynamic resource: SDK docs by language ---
server.resource("SDK README by Language", new ResourceTemplate("srcfile://docs/sdk/{language}", { list: undefined }), { description: "SDK documentation for a specific language (python, javascript, go)" }, (uri, { language }) => {
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
});
// ===========================
// PROMPTS
// ===========================
server.prompt("analyze_scan_result", "Analyze a SrcFile scan result and provide a security assessment with recommended actions.", { scan_json: z.string().describe("The JSON scan result to analyze") }, ({ scan_json }) => ({
    messages: [
        {
            role: "user",
            content: {
                type: "text",
                text: `Analyze this SrcFile scan result and provide:
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
}));
server.prompt("generate_sdk_code", "Generate code using a SrcFile SDK for a given use case.", {
    language: z.enum(["python", "javascript", "go"]).describe("SDK language"),
    use_case: z.string().describe("What the code should do (e.g. 'scan all PDFs in a directory', 'set up webhook handler')"),
}, ({ language, use_case }) => ({
    messages: [
        {
            role: "user",
            content: {
                type: "text",
                text: `Generate ${language} code using the SrcFile ${language} SDK for the following use case:

${use_case}

Use the official SDK patterns (proper imports, error handling, auth via SRCFILE_KEY env var). Include brief comments explaining each step. Make the code production-ready.`,
            },
        },
    ],
}));
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
