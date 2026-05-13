#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# OWASP CRS smoke tests
#
# Tests two layers of blocking:
#   1. Custom rules (rules.conf, phase:1 deny)   — immediate block
#   2. CRS rules   (useOWASPCRS: true, phase:2)  — anomaly scoring block
#      CRS uses anomaly scoring: each rule adds to a score; rule 949110
#      blocks at the end of phase 2 when score >= threshold (default: 5).
#      A single CRITICAL rule hit (e.g. 942100 SQLi via libinjection) adds
#      5 points — exactly the threshold — so one match = block.
#
# Usage: ./test.sh [base_url]   default: http://localhost
# ---------------------------------------------------------------------------
set -euo pipefail

BASE="${1:-http://localhost}"
PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
DIM='\033[2m'
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
echo -e "${CYAN}=== OWASP CRS smoke tests against $BASE ===${NC}"
echo -e "${DIM}CRS v4.25.0 · paranoia level 1 · anomaly threshold 5${NC}"
echo ""

# ---------------------------------------------------------------------------
# PASS — legitimate traffic must reach the backend
# ---------------------------------------------------------------------------
echo -e "${DIM}--- Pass-through ---${NC}"

assert "Normal GET / → 200" 200 \
    "$(http_code "$BASE/")"

assert "Normal GET /hello → 200" 200 \
    "$(http_code "$BASE/hello")"

assert "Normal POST with JSON body → 200" 200 \
    "$(http_code -X POST \
        -H 'Content-Type: application/json' \
        -d '{"user":"alice","action":"login"}' \
        "$BASE/api/login")"

assert "Normal query params → 200" 200 \
    "$(http_code "$BASE/search?q=hello+world&page=1")"

# ---------------------------------------------------------------------------
# CUSTOM RULE BLOCKS (phase:1 deny — fires before CRS anomaly scoring)
# Status 401 distinguishes custom-rule blocks from CRS blocks (403).
# ---------------------------------------------------------------------------
echo ""
echo -e "${DIM}--- Custom rule blocks (phase 1, immediate deny) ---${NC}"

assert "Custom rule 1001: /blockme → 401" 401 \
    "$(http_code "$BASE/blockme")"

assert "Custom rule 1001: /api/blockme/data → 401" 401 \
    "$(http_code "$BASE/api/blockme/data")"

# ---------------------------------------------------------------------------
# CRS BLOCKS — SQL injection
#
# All payloads hit rule 942100 (libinjection) and/or 942200 (pattern match),
# both CRITICAL (+5). Anomaly threshold is 5, so one hit = block at phase 2.
# ---------------------------------------------------------------------------
echo ""
echo -e "${DIM}--- CRS: SQL injection (rule 942100 / 942200, CRITICAL +5) ---${NC}"

# Classic tautology — detected by libinjection (rule 942100)
assert "CRS SQLi: tautology in query param → 403" 403 \
    "$(http_code --data-urlencode "q=1' OR '1'='1" -G "$BASE/search")"

# UNION SELECT — detected by pattern rules (rule 942200 family)
assert "CRS SQLi: UNION SELECT in query param → 403" 403 \
    "$(http_code --data-urlencode "q=1 UNION SELECT username,password FROM users--" -G "$BASE/search")"

# SQL injection in POST body — uses a payload NOT matching our custom rule 1004
# (which only matches 'drop table') to confirm CRS detects it independently.
assert "CRS SQLi: tautology in POST body field → 403" 403 \
    "$(http_code -X POST \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "username=admin&password=1' OR '1'='1" \
        "$BASE/login")"

# Boolean AND tautology in a different field — same libinjection fingerprint as the
# OR tautology above but uses AND, confirming both conjunction operators are detected.
# "1; SELECT * FROM users--" (stacked query) is intentionally avoided: the bare
# semicolon+SELECT pattern is not in libinjection's PL1 fingerprint set and CRS's
# direct-match rules at PL1 target UNION/BENCHMARK/SLEEP, not plain SELECT.
assert "CRS SQLi: AND tautology in POST body → 403" 403 \
    "$(http_code -X POST \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "id=1' AND '1'='1" \
        "$BASE/api/user")"

# ---------------------------------------------------------------------------
# CRS BLOCKS — Cross-site scripting
#
# Rule 941100 (XSS via libinjection) and 941160 (NoScript) are CRITICAL.
# Note: our custom rule 1005 would also match <script> in ARGS, but it
# was intentionally omitted from this ruleset to keep it CRS-focused.
# ---------------------------------------------------------------------------
echo ""
echo -e "${DIM}--- CRS: Cross-site scripting (rule 941100 / 941160, CRITICAL +5) ---${NC}"

assert "CRS XSS: <script> tag in query param → 403" 403 \
    "$(http_code --data-urlencode "q=<script>alert(document.cookie)</script>" -G "$BASE/search")"

assert "CRS XSS: event handler injection → 403" 403 \
    "$(http_code --data-urlencode 'q="><img src=x onerror=alert(1)>' -G "$BASE/search")"

# ---------------------------------------------------------------------------
echo ""
echo -e "${CYAN}=== Results: $PASS passed, $FAIL failed ===${NC}"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${DIM}Troubleshooting tips:${NC}"
    echo -e "${DIM}  • CRS blocks appear in Traefik logs at DEBUG level — check 'docker compose logs traefik'${NC}"
    echo -e "${DIM}  • CRS anomaly blocks fire at phase 2 (rule 949110) — earlier phases log individual matches${NC}"
    echo -e "${DIM}  • Ensure the image was rebuilt after adding useOWASPCRS: true to the config${NC}"
    echo ""
fi

[ "$FAIL" -eq 0 ]
