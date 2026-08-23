#!/usr/bin/env bash
#
# Package the Claude Desktop extension (surface.mcpb) and publish it into the
# LOCAL public-tools bucket.
#
# An .mcpb is a zip with manifest.json at the root plus whatever the entry point
# needs at runtime — here dist/ and the production node_modules. Claude Desktop
# opens the file directly and prompts for the API key described in the
# manifest's user_config.
#
# The platform serves it unauthenticated from
#   <app>/api/public/tools/surface-mcp/v1/<version>/surface.mcpb
# the same channel as the scanner and dev-mcp binaries. The source repo is
# private, so GitHub releases are not a distribution option — see the note in
# tendrl-dev-mcp/.github/workflows/release.yml.
#
# Usage: ./publish-local.sh [version]        (default: latest)
#
# Requires: node/npm, zip, aws CLI, and MinIO on :9000.

set -euo pipefail

VERSION="${1:-latest}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="${HERE}/.mcpb-stage"
DIST="${HERE}/dist-local"

: "${S3_ENDPOINT_URL:=http://localhost:9000}"
: "${AWS_ACCESS_KEY_ID:=minioadmin}"
: "${AWS_SECRET_ACCESS_KEY:=minioadmin}"
: "${AWS_REGION:=us-east-1}"
: "${PUBLIC_TOOLS_BUCKET:=tendrl-public-tools-us-1}"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_REGION

cd "$HERE"
rm -rf "$STAGE" "$DIST"; mkdir -p "$STAGE" "$DIST"

echo "==> building the server"
npm run build --silent

echo "==> staging bundle"
cp manifest.json package.json "$STAGE/"
cp -R dist "$STAGE/dist"
[[ -f README.md ]] && cp README.md "$STAGE/"
[[ -f LICENSE ]] && cp LICENSE "$STAGE/"
# Runtime dependencies only — dev deps (typescript, @types) would roughly double
# the bundle for no runtime benefit.
( cd "$STAGE" && npm install --omit=dev --no-audit --no-fund --silent )

echo "==> packing surface.mcpb"
( cd "$STAGE" && zip -qr "$DIST/surface.mcpb" . -x '*.DS_Store' )

( cd "$DIST" && shasum -a 256 * > SHA256SUMS.txt 2>/dev/null || sha256sum * > SHA256SUMS.txt )

echo "==> writing manifest.json"
# Same shape as toolManifest in tendrl-contact/app_service/api/public_tools.go.
# The extension is one cross-platform bundle, so it declares platform "any"
# rather than an <os>-<arch> pair.
python3 - "$VERSION" "$DIST" <<'PY'
import hashlib, json, os, sys
version, dist = sys.argv[1], sys.argv[2]
path = os.path.join(dist, "surface.mcpb")
with open(path, "rb") as fh:
    digest = hashlib.sha256(fh.read()).hexdigest()
manifest = {
    "version": version,
    "released": "",
    "files": [{
        "platform": "any",
        "filename": "surface.mcpb",
        "sha256": digest,
        "size": os.path.getsize(path),
    }],
}
with open(os.path.join(dist, "manifest.json"), "w") as fh:
    json.dump(manifest, fh, indent=2)
print(json.dumps(manifest, indent=2))
PY

echo "==> uploading to ${PUBLIC_TOOLS_BUCKET}/surface-mcp/${VERSION}/"
aws --endpoint-url "$S3_ENDPOINT_URL" s3 sync "$DIST/" \
  "s3://${PUBLIC_TOOLS_BUCKET}/surface-mcp/${VERSION}/" --delete --no-progress

rm -rf "$STAGE"

echo
echo "done. verify with:"
echo "  curl -s http://localhost:8000/api/public/tools/surface-mcp/v1/meta | python3 -m json.tool"
