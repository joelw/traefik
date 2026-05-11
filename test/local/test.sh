#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Coraza WAF smoke tests
# Run from this directory after `docker compose up -d` completes.
# Usage: ./test.sh [base_url]   default base_url: http://localhost
# ---------------------------------------------------------------------------
set -euo pipefail

BASE="${1:-http://localhost}"
PASS=0
FAIL=0

# Colours
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

assert() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC}  $desc  (got $actual)"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC}  $desc  (expected $expected, got $actual)"
        FAIL=$((FAIL + 1))
    fi
}

http_code() {
    curl -s -o /dev/null -w "%{http_code}" "$@"
}

echo ""
echo "=== Coraza WAF smoke tests against $BASE ==="
echo ""

# ---- PASS cases (traffic that should reach nginx) -------------------------

assert "Normal GET / → 200" 200 \
    "$(http_code "$BASE/")"

assert "Normal GET /hello → 200" 200 \
    "$(http_code "$BASE/hello")"

assert "Normal POST /api → 200" 200 \
    "$(http_code -X POST -d '{"key":"value"}' -H 'Content-Type: application/json' "$BASE/api")"

# ---- BLOCK cases (rules.conf) ---------------------------------------------

# Rule 1001 — blockme in URI path
assert "Rule 1001: /blockme → 401" 401 \
    "$(http_code "$BASE/blockme")"

# Rule 1001 — blockme in a subdirectory
assert "Rule 1001: /foo/blockme/bar → 401" 401 \
    "$(http_code "$BASE/foo/blockme/bar")"

# Rule 1001 — blockme in query string (REQUEST_URI includes query string)
assert "Rule 1001: /?q=blockme → 401" 401 \
    "$(http_code "$BASE/?q=blockme")"

# Rule 1002 — bad User-Agent
assert "Rule 1002: User-Agent badbot → 403" 403 \
    "$(http_code -H 'User-Agent: badbot/1.0' "$BASE/")"

# Rule 1003 — X-Attack header
assert "Rule 1003: X-Attack header → 403" 403 \
    "$(http_code -H 'X-Attack: anything' "$BASE/")"

# Rule 1004 — SQL injection in POST body
assert "Rule 1004: 'drop table' in body → 403" 403 \
    "$(http_code -X POST -d 'input=drop table users' -H 'Content-Type: application/x-www-form-urlencoded' "$BASE/api")"

# Rule 1005 — XSS probe in query arg
assert "Rule 1005: <script> in query arg → 403" 403 \
    "$(http_code --data-urlencode 'q=<script>alert(1)</script>' -G "$BASE/search")"

# ---- ALLOW + LOG — rule fires and logs, but does not block ----------------
# Rule 1006 matches /allowme with allow,log. The request must reach nginx (200)
# AND the WAF must have fired the log callback (action=allowed in Traefik logs).
# We verify the HTTP side here; log presence is checked separately below.

assert "Rule 1006: allow,log on /allowme → 200 (not blocked)" 200 \
    "$(http_code "$BASE/allowme")"

# Advisory: grep Traefik container logs for the rule 1006 log entry.
# Requires docker compose to be running from this directory.
if docker compose logs --no-log-prefix traefik 2>/dev/null \
        | sed 's/\x1b\[[0-9;]*m//g' \
        | grep -q "rule_id=1006"; then
    echo -e "${GREEN}PASS${NC}  Rule 1006: log entry found in Traefik logs  (action=allowed)"
    PASS=$((PASS + 1))
else
    echo -e "${RED}FAIL${NC}  Rule 1006: log entry NOT found in Traefik logs"
    echo        "       (check Traefik log level is DEBUG or INFO, and rebuild after code changes)"
    FAIL=$((FAIL + 1))
fi

# ---- PHASE 3 — response header inspection ---------------------------------
# nginx /test/response-header returns X-Internal-Data: leaked_token=abc123secret
# Rule 2001 matches RESPONSE_HEADERS:X-Internal-Data in phase:3 and blocks it.
# The backend returns 200; Traefik substitutes 403 after WAF phase 3 fires.

assert "Phase 3 pass: normal response header → 200" 200 \
    "$(http_code "$BASE/")"

assert "Rule 2001: leaked token in response header → 403" 403 \
    "$(http_code "$BASE/test/response-header")"

# ---- PHASE 4 — response body inspection -----------------------------------
# nginx /test/response-body returns JSON containing db_password=...
# Rule 2002 matches RESPONSE_BODY "@contains db_password=" in phase:4.
# The backend returns 200; Traefik substitutes 403 after WAF phase 4 fires.

assert "Phase 4 pass: normal response body → 200" 200 \
    "$(http_code "$BASE/hello")"

assert "Rule 2002: credential pattern in response body → 403" 403 \
    "$(http_code "$BASE/test/response-body")"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
echo ""

[ "$FAIL" -eq 0 ]
