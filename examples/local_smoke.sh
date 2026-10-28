#!/usr/bin/env bash
# Local boot check for the A2 spike: a bb-identity broker on loopback 8775
# (fake Salesforce settings, no sign-in possible) and examples/spike_server.py
# on 8776 in required mode, then probes. Nothing leaves the machine.
#
#   bash examples/local_smoke.sh            # bb-identity checked out next to this repo, built (npm run build)
#   BB_IDENTITY_DIR=/path/to/bb-identity bash examples/local_smoke.sh
#
# Expect: jwks 200, AS metadata for /r/spike, snapshot 200 with the verifier
# token and 401 without, the spike's protected-resource metadata naming the
# broker, and 401 + WWW-Authenticate on /mcp with no token or a junk one.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ID="${BB_IDENTITY_DIR:-$HERE/../bb-identity}"
[ -f "$ID/dist/index.js" ] || { echo "build bb-identity first: (cd $ID && npm ci && npm run build)"; exit 1; }
W=$(mktemp -d)

TOK=$(node -e "const c=require('crypto');const t='bbv_spike_'+c.randomBytes(32).toString('base64url');console.log(t+' '+c.createHash('sha256').update(t).digest('hex'))")
VT=${TOK% *}
VH=${TOK#* }
cat > "$W/resources.json" <<EOF
{ "apps": { "spike": { "display_name": "Spike", "resource": "http://127.0.0.1:8776/mcp", "permission_app": "Spike",
  "tiers": [ { "name": "Read", "scopes": ["spike:read"] } ], "verifier_token_sha256": "$VH" } } }
EOF
openssl genrsa -out "$W/status.key" 2048 2>/dev/null

export IDENTITY_PUBLIC_URL=http://127.0.0.1:8775
IDENTITY_SECRET=$(openssl rand -base64 32)
IDENTITY_ADMIN_TOKEN=$(openssl rand -base64 32)
export IDENTITY_SECRET IDENTITY_ADMIN_TOKEN
export DB_PATH="$W/id.sqlite" IDENTITY_KEYS_PATH="$W/keys.json" IDENTITY_SNAPSHOT_PATH="$W/snapshot.json"
export IDENTITY_RESOURCES_PATH="$W/resources.json" IDENTITY_SF_STATUS_KEY_PATH="$W/status.key"
export IDENTITY_SF_ORG_ID=00D000000000000AAA IDENTITY_SF_LOGIN_CLIENT_ID=fake IDENTITY_SF_STATUS_CLIENT_ID=fake
export IDENTITY_SF_STATUS_USERNAME=status@example.invalid IDENTITY_SF_LOGIN_URL=http://127.0.0.1:9 IDENTITY_SF_HTTP_TIMEOUT_MS=1000

(cd "$ID" && node dist/index.js > "$W/broker.log" 2>&1) &
BPID=$!
sleep 4
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
echo "broker ready:            $(grep -c 'bb-identity ready' "$W/broker.log")"
echo "jwks:                    $(code http://127.0.0.1:8775/.well-known/jwks.json)"
echo "AS metadata /r/spike:    $(code http://127.0.0.1:8775/.well-known/oauth-authorization-server/r/spike)"
echo "snapshot, verifier token: $(code -H "Authorization: Bearer $VT" http://127.0.0.1:8775/r/spike/snapshot)"
echo "snapshot, no token:      $(code http://127.0.0.1:8775/r/spike/snapshot)"

export SPIKE_IDENTITY_MODE=required SPIKE_IDENTITY_ISSUER=http://127.0.0.1:8775/r/spike
export SPIKE_IDENTITY_RESOURCE=http://127.0.0.1:8776/mcp SPIKE_IDENTITY_VERIFIER_TOKEN="$VT"
export SPIKE_IDENTITY_SNAPSHOT_URL=http://127.0.0.1:8775/r/spike/snapshot SPIKE_IDENTITY_JWKS_URL=http://127.0.0.1:8775/.well-known/jwks.json
(cd "$HERE" && uv run --extra examples python -W ignore examples/spike_server.py --port 8776 > "$W/spike.log" 2>&1) &
SPID=$!
sleep 8
echo "protected-resource:      $(curl -s http://127.0.0.1:8776/.well-known/oauth-protected-resource)"
echo "/mcp, no token:          $(code -X POST http://127.0.0.1:8776/mcp -H 'Content-Type: application/json' -d '{}')"
echo "/mcp, junk token:        $(code -X POST http://127.0.0.1:8776/mcp -H 'Authorization: Bearer junk' -H 'Content-Type: application/json' -d '{}')"

kill "$SPID" "$BPID" 2>/dev/null
if command -v taskkill >/dev/null 2>&1; then  # Git Bash: the node / python children outlive the subshells
  for p in 8775 8776; do
    pid=$(netstat -ano | grep "127.0.0.1:$p .*LISTENING" | awk '{print $5}' | head -1)
    [ -n "$pid" ] && taskkill //F //PID "$pid" >/dev/null 2>&1
  done
else
  pkill -f "examples/spike_server.py --port 8776" 2>/dev/null
  pkill -f "$ID/dist/index.js" 2>/dev/null
fi
rm -rf "$W"
