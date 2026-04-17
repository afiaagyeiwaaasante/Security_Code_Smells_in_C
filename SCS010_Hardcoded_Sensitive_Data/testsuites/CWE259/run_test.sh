#!/usr/bin/env bash
# run_test.sh
# CWE-259 Hardcoded Sensitive Data — SmellDetect test runner
#
# Runs smell_report.sh on every test case, collects results, and prints
# a pass/fail summary table.
#
# Expected:
#   bad_*.c / bad_*.cpp   →  at least one finding, any severity (TP)
#   good_*.c / good_*.cpp →  zero findings (TN)
#
# Note: all SCS010 findings are error/vulnerability (hardcoded credentials are
#       always exploitable by design). No smell_ variants exist for this detector.
#
# Usage: bash run_test.sh [output_dir]
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SMELL_REPORT="$PROJECT_ROOT/src/smell_report.sh"
OUTPUT_DIR="${1:-$SCRIPT_DIR/results}"

mkdir -p "$OUTPUT_DIR"

PASS=0
FAIL=0
TOTAL=0

declare -a RESULTS

run_case() {
    local src="$1"
    local expect="$2"   # "bad" or "good"
    local base; base=$(basename "$src")

    bash "$SMELL_REPORT" "$src" "$OUTPUT_DIR" > /dev/null 2>&1

    local findings_file
    findings_file=$(ls -t "$OUTPUT_DIR/${base%.*}_findings_"*.json 2>/dev/null | head -1)

    local count=0
    if [ -f "$findings_file" ]; then
        count=$(python3 -c "
import json, sys
content = open('$findings_file').read().strip()
findings = []
depth, buf = 0, ''
for ch in content:
    if ch == '{': depth += 1
    if depth > 0: buf += ch
    if ch == '}':
        depth -= 1
        if depth == 0 and buf.strip():
            try: findings.append(json.loads(buf))
            except: pass
            buf = ''
print(len(findings))
" 2>/dev/null || echo 0)
    fi

    local status
    if [ "$expect" = "bad" ] && [ "$count" -gt 0 ]; then
        status="PASS (TP)"
        PASS=$((PASS + 1))
    elif [ "$expect" = "good" ] && [ "$count" -eq 0 ]; then
        status="PASS (TN)"
        PASS=$((PASS + 1))
    elif [ "$expect" = "bad" ] && [ "$count" -eq 0 ]; then
        status="FAIL (FN)"
        FAIL=$((FAIL + 1))
    else
        status="FAIL (FP)"
        FAIL=$((FAIL + 1))
    fi

    TOTAL=$((TOTAL + 1))
    RESULTS+=("$(printf '%-50s  %-8s  %s' "$base" "$expect" "$status")")
}

echo "========================================"
echo " CWE-259 Hardcoded Sensitive Data — Test Suite"
echo " Tool   : smell_report.sh"
echo " Date   : $(date)"
echo "========================================"
echo

# --- password_var group ---
echo "[ password_var ]"
for f in "$SCRIPT_DIR/password_var"/bad_*.c;  do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/password_var"/good_*.c; do [ -f "$f" ] && run_case "$f" good; done

# --- define_const group ---
echo "[ define_const ]"
for f in "$SCRIPT_DIR/define_const"/bad_*.c;  do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/define_const"/good_*.c; do [ -f "$f" ] && run_case "$f" good; done

# --- strcmp_auth group ---
echo "[ strcmp_auth ]"
for f in "$SCRIPT_DIR/strcmp_auth"/bad_*.c;  do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/strcmp_auth"/good_*.c; do [ -f "$f" ] && run_case "$f" good; done

# --- cpp_class group (flow 84) ---
echo "[ cpp_class ]"
for f in "$SCRIPT_DIR/cpp_class"/bad_*.cpp;  do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/cpp_class"/good_*.cpp; do [ -f "$f" ] && run_case "$f" good; done

# --- interprocedural group (sink file only — source credential set in 22a) ---
# NOTE: 22a files contain only the credential assignment, no authentication sink —
# single-file analysis cannot detect them. Only 22b (sink side) is tested here.
echo "[ interprocedural ]"
for f in "$SCRIPT_DIR/interprocedural"/bad_*_22b.c;  do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/interprocedural"/good_*_22b.c; do [ -f "$f" ] && run_case "$f" good; done

echo
echo "========================================"
echo " Results"
echo "========================================"
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo
echo "  Total: $TOTAL   Pass: $PASS   Fail: $FAIL"
echo "========================================"
