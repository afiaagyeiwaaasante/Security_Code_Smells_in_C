#!/usr/bin/env bash
# run_test.sh
# CWE-190 Integer Overflow Risk — Our Tool test runner
#
# Runs smell_report.sh on every test case, collects results, and prints
# a pass/fail summary table.
#
# Expected:
#   bad_*.c / bad_*.cpp  →  at least one finding (TP)
#   good_*.c / good_*.cpp → zero findings (TN)
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
    local dir;  dir=$(dirname "$src")
    local findings_tmp; findings_tmp=$(mktemp /tmp/cwe190_test_XXXXXX)

    bash "$SMELL_REPORT" "$src" "$OUTPUT_DIR" > /dev/null 2>&1

    # Find the latest findings file for this source
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
    rm -f "$findings_tmp"
}

echo "========================================"
echo " CWE-190 Integer Overflow — Test Suite"
echo " Tool   : smell_report.sh"
echo " Date   : $(date)"
echo "========================================"
echo

# --- add group ---
echo "[ add ]"
for f in "$SCRIPT_DIR/add"/bad_*.c; do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/add"/good_*.c; do [ -f "$f" ] && run_case "$f" good; done

# --- multiply group ---
echo "[ multiply ]"
for f in "$SCRIPT_DIR/multiply"/bad_*.c; do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/multiply"/good_*.c; do [ -f "$f" ] && run_case "$f" good; done

# --- square group ---
echo "[ square ]"
for f in "$SCRIPT_DIR/square"/bad_*.c; do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/square"/good_*.c; do [ -f "$f" ] && run_case "$f" good; done

# --- postinc group ---
echo "[ postinc ]"
for f in "$SCRIPT_DIR/postinc"/bad_*.c; do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/postinc"/good_*.c; do [ -f "$f" ] && run_case "$f" good; done

# --- preinc group ---
echo "[ preinc ]"
for f in "$SCRIPT_DIR/preinc"/bad_*.c; do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/preinc"/good_*.c; do [ -f "$f" ] && run_case "$f" good; done

# --- C++ virtual ref (flow 81) ---
echo "[ cpp_virtual_ref ]"
for f in "$SCRIPT_DIR/cpp_virtual_ref"/bad_*.cpp; do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/cpp_virtual_ref"/good_*.cpp; do [ -f "$f" ] && run_case "$f" good; done

# --- C++ virtual ptr (flow 82) ---
echo "[ cpp_virtual_ptr ]"
for f in "$SCRIPT_DIR/cpp_virtual_ptr"/bad_*.cpp; do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/cpp_virtual_ptr"/good_*.cpp; do [ -f "$f" ] && run_case "$f" good; done

# --- C++ ctor stack (flow 83) ---
echo "[ cpp_ctor_stack ]"
for f in "$SCRIPT_DIR/cpp_ctor_stack"/bad_*.cpp; do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/cpp_ctor_stack"/good_*.cpp; do [ -f "$f" ] && run_case "$f" good; done

# --- C++ ctor heap (flow 84) ---
echo "[ cpp_ctor_heap ]"
for f in "$SCRIPT_DIR/cpp_ctor_heap"/bad_*.cpp; do [ -f "$f" ] && run_case "$f" bad; done
for f in "$SCRIPT_DIR/cpp_ctor_heap"/good_*.cpp; do [ -f "$f" ] && run_case "$f" good; done

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
