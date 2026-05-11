#!/usr/bin/env bash
# =============================================================================
# Coraza WAF performance benchmark
#
# Runs ApacheBench against two Traefik entrypoints on the same binary:
#   :80   WAF ON  (CorazaWAF middleware in the chain)
#   :8081 WAF OFF (bare Traefik → nginx, no middleware)
#
# Usage:
#   ./bench.sh [options]
#
# Options:
#   -n REQUESTS     Total requests per URL (default: 3000)
#   -c CONCURRENCY  Concurrent workers    (default: 20)
#   -w WARMUP       Warmup requests       (default: 300)
#   -H HOST         Target host           (default: 127.0.0.1)
#   -h              Show this help
#
# Requires: ab (ApacheBench)  — macOS: /usr/sbin/ab   Linux: apache2-utils
# =============================================================================
set -euo pipefail

# ---- defaults ---------------------------------------------------------------
REQUESTS=3000
CONCURRENCY=20
WARMUP=300
HOST="127.0.0.1"
WAF_PORT=80
BARE_PORT=8081

usage() {
    sed -n '/^# Usage:/,/^# Requires:/p' "$0" | sed 's/^# \?//'
    exit 0
}

while getopts "n:c:w:H:h" opt; do
    case $opt in
        n) REQUESTS=$OPTARG ;;
        c) CONCURRENCY=$OPTARG ;;
        w) WARMUP=$OPTARG ;;
        H) HOST=$OPTARG ;;
        h) usage ;;
        *) usage ;;
    esac
done

WAF_BASE="http://${HOST}:${WAF_PORT}"
BARE_BASE="http://${HOST}:${BARE_PORT}"

# ---- colours ----------------------------------------------------------------
BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---- preflight --------------------------------------------------------------
if ! command -v ab &>/dev/null; then
    echo "ab not found. Install with:"
    echo "  macOS:  ab is at /usr/sbin/ab — add /usr/sbin to PATH"
    echo "  Debian: sudo apt install apache2-utils"
    echo "  RHEL:   sudo dnf install httpd-tools"
    exit 1
fi

wait_for() {
    local url="$1" label="$2" retries=30
    printf "Waiting for %s" "$label"
    while ! curl -sf -o /dev/null "$url" 2>/dev/null; do
        retries=$((retries - 1))
        [ $retries -eq 0 ] && echo -e "\n${RED}Timed out waiting for $label${NC}" && exit 1
        printf "."
        sleep 2
    done
    echo " ready."
}

echo ""
echo -e "${BOLD}=== Coraza WAF Benchmark ===${NC}"
echo -e "${DIM}Requests: ${REQUESTS}  Concurrency: ${CONCURRENCY}  Warmup: ${WARMUP}${NC}"
echo ""

wait_for "${WAF_BASE}/"   "WAF ON  (:${WAF_PORT})"
wait_for "${BARE_BASE}/"  "WAF OFF (:${BARE_PORT})"
echo ""

# ---- URL definitions --------------------------------------------------------
# Each entry: "label|path"
# PASS  — legitimate traffic, reaches nginx backend
# BLOCK — matched by a WAF rule; WAF rejects before touching the backend
# NEAR  — plausible-looking paths that exercise the ruleset without matching

PASS_URLS=(
    "Normal GET /             |/"
    "Normal GET /hello        |/hello"
    "Normal GET /api/v1/users |/api/v1/users"
    "Normal GET /static/x.css |/static/style.css"
)

BLOCK_URLS=(
    "Block: /blockme (rule 1001)     |/blockme"
    "Block: /api/blockme (rule 1001) |/api/blockme/data"
    "Block: ?q=blockme (rule 1001)   |/?q=blockme"
)

NEAR_URLS=(
    "Near-miss: /block                |/block"
    "Near-miss: /api/data?q=search   |/api/data?q=search"
    "Near-miss: /api/data?format=json |/api/data?format=json"
)

# ---- ab runner --------------------------------------------------------------
# run_ab <base_url> <path> <n> <c>
# Prints to stdout the full ab output.
run_ab() {
    local base="$1" path="$2" n="$3" c="$4"
    ab -n "$n" -c "$c" -q -k "${base}${path}" 2>/dev/null || true
}

# parse_rps <ab_output>  → integer req/sec
parse_rps() {
    echo "$1" | grep "^Requests per second" | awk '{printf "%.0f", $4}' || echo "0"
}

# parse_p50 <ab_output>  → ms (mean time per request)
parse_p50() {
    echo "$1" | grep "^ *50%" | awk '{print $2}' || echo "?"
}

# parse_p99 <ab_output>  → ms
parse_p99() {
    echo "$1" | grep "^ *99%" | awk '{print $2}' || echo "?"
}

# overhead_pct <waf_rps> <bare_rps>  → e.g. "-42"  (negative = slower)
overhead_pct() {
    local waf="$1" bare="$2"
    awk -v w="$waf" -v b="$bare" 'BEGIN {
        if (b == 0) { print "n/a"; exit }
        pct = (w - b) / b * 100
        printf "%+.0f%%", pct
    }'
}

overhead_colour() {
    local pct="$1"
    local n
    n=$(echo "$pct" | tr -d '%+')
    if   [ "$n" -ge  -10 ] 2>/dev/null; then echo -e "${GREEN}${pct}${NC}"
    elif [ "$n" -ge  -30 ] 2>/dev/null; then echo -e "${YELLOW}${pct}${NC}"
    else                                      echo -e "${RED}${pct}${NC}"
    fi
}

# ---- warmup -----------------------------------------------------------------
echo -e "${DIM}Warming up both entrypoints...${NC}"
run_ab "$WAF_BASE"  "/" "$WARMUP" "$CONCURRENCY" > /dev/null
run_ab "$BARE_BASE" "/" "$WARMUP" "$CONCURRENCY" > /dev/null
echo ""

# ---- benchmark loop ---------------------------------------------------------
# Accumulate totals for summary averages
pass_waf_total=0;  pass_bare_total=0;  pass_count=0
block_waf_total=0; block_bare_total=0; block_count=0
near_waf_total=0;  near_bare_total=0;  near_count=0

# Column widths
LW=38   # label width

print_header() {
    local section="$1"
    printf "\n${BOLD}%-${LW}s  %9s  %9s  %7s  %6s  %6s${NC}\n" \
        "$section" "WAF-ON r/s" "Bare r/s" "Diff" "p99-W" "p99-B"
    printf '%0.s─' $(seq 1 90); echo
}

bench_url() {
    local label="$1" path="$2" category="$3"
    printf "  %-$((LW-2))s  " "$label"

    local waf_out bare_out
    waf_out=$(run_ab  "$WAF_BASE"  "$path" "$REQUESTS" "$CONCURRENCY")
    bare_out=$(run_ab "$BARE_BASE" "$path" "$REQUESTS" "$CONCURRENCY")

    local waf_rps bare_rps waf_p99 bare_p99 pct coloured_pct
    waf_rps=$(parse_rps  "$waf_out")
    bare_rps=$(parse_rps "$bare_out")
    waf_p99=$(parse_p99  "$waf_out")
    bare_p99=$(parse_p99 "$bare_out")
    pct=$(overhead_pct "$waf_rps" "$bare_rps")
    coloured_pct=$(overhead_colour "$pct")

    printf "%9s  %9s  " "$waf_rps" "$bare_rps"
    printf "%s" "$coloured_pct"
    # pad after coloured string (colour codes are invisible width)
    printf "%$((7 - ${#pct}))s" ""
    printf "  %5sms  %5sms\n" "$waf_p99" "$bare_p99"

    # accumulate
    case "$category" in
        pass)
            pass_waf_total=$((pass_waf_total  + waf_rps))
            pass_bare_total=$((pass_bare_total + bare_rps))
            pass_count=$((pass_count + 1))
            ;;
        block)
            block_waf_total=$((block_waf_total  + waf_rps))
            block_bare_total=$((block_bare_total + bare_rps))
            block_count=$((block_count + 1))
            ;;
        near)
            near_waf_total=$((near_waf_total  + waf_rps))
            near_bare_total=$((near_bare_total + bare_rps))
            near_count=$((near_count + 1))
            ;;
    esac
}

# ---- PASS traffic -----------------------------------------------------------
print_header "Pass-through traffic (reaches nginx backend)"
for entry in "${PASS_URLS[@]}"; do
    label="${entry%%|*}"
    path="${entry##*|}"
    bench_url "$label" "$path" "pass"
done

# ---- BLOCK traffic ----------------------------------------------------------
print_header "Blocked traffic (WAF rejects before backend)"
for entry in "${BLOCK_URLS[@]}"; do
    label="${entry%%|*}"
    path="${entry##*|}"
    bench_url "$label" "$path" "block"
done

# ---- NEAR-MISS traffic ------------------------------------------------------
print_header "Near-miss traffic (ruleset exercises but no match)"
for entry in "${NEAR_URLS[@]}"; do
    label="${entry%%|*}"
    path="${entry##*|}"
    bench_url "$label" "$path" "near"
done

# ---- summary ----------------------------------------------------------------
avg() {
    local total="$1" count="$2"
    [ "$count" -eq 0 ] && echo 0 && return
    echo $((total / count))
}

echo ""
printf '%0.s═' $(seq 1 90); echo
echo -e "${BOLD}Summary (averages)${NC}"
printf '%0.s─' $(seq 1 90); echo

print_summary_row() {
    local label="$1" waf_avg="$2" bare_avg="$3"
    local pct coloured_pct
    pct=$(overhead_pct "$waf_avg" "$bare_avg")
    coloured_pct=$(overhead_colour "$pct")
    printf "  %-$((LW-2))s  %9s  %9s  " "$label" "$waf_avg" "$bare_avg"
    printf "%s\n" "$coloured_pct"
}

print_summary_row \
    "Pass-through (legitimate traffic overhead)" \
    "$(avg "$pass_waf_total"  "$pass_count")" \
    "$(avg "$pass_bare_total" "$pass_count")"

print_summary_row \
    "Blocked (WAF fast-reject, no backend call)" \
    "$(avg "$block_waf_total"  "$block_count")" \
    "$(avg "$block_bare_total" "$block_count")"

print_summary_row \
    "Near-miss (ruleset scan, all rules evaluated)" \
    "$(avg "$near_waf_total"  "$near_count")" \
    "$(avg "$near_bare_total" "$near_count")"

echo ""
echo -e "${DIM}Overhead %: WAF-ON vs bare Traefik (same binary, same backend).${NC}"
echo -e "${DIM}  ${GREEN}≥ -10%${NC}${DIM}  negligible    ${YELLOW}-10% to -30%${NC}${DIM}  moderate    ${RED}< -30%${NC}${DIM}  significant${NC}"
echo ""
echo -e "${DIM}Notes:${NC}"
echo -e "${DIM}  • Blocked req/sec may be HIGHER than bare because WAF short-circuits before the backend.${NC}"
echo -e "${DIM}  • To test with OWASP CRS, update coraza/rules.conf and restart the stack.${NC}"
echo -e "${DIM}  • Increase -n/-c for tighter confidence intervals (e.g. ./bench.sh -n 10000 -c 50).${NC}"
echo ""
