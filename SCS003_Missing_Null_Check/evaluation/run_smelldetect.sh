#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS003 tool on each CWE-476 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE476"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

SMELL_REPORT="$SRC_DIR/smell_report.sh"
SMELL_REPORT_MULTI="$SRC_DIR/smell_report_multi.sh"

> "$RESULTS"   # clear previous results

echo "========================================"
echo " SCS003 — SmellDetect Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

# -----------------------------------------------------------------------
# Helper: run tool on one or more files, capture time + memory + detection
# -----------------------------------------------------------------------
run_case() {
    local TEST_NAME="$1"
    local TIER="$2"
    local EXPECTED="$3"
    local MODE="$4"          # single | multi
    shift 4
    local FILES=("$@")

    echo "--- [$TIER] $TEST_NAME (expected: $EXPECTED) ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/smelldetect_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/smelldetect_time_XXXXXX)

    if [ "$MODE" = "single" ]; then
        /usr/bin/time -l bash "$SMELL_REPORT" "${FILES[0]}" \
            > "$TMPOUT" 2>"$TIMEFILE" || true
    else
        /usr/bin/time -l bash "$SMELL_REPORT_MULTI" "${FILES[@]}" \
            > "$TMPOUT" 2>"$TIMEFILE" || true
    fi

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    local FINDING_COUNT DETECTED
    if [ "$MODE" = "single" ]; then
        FINDING_COUNT=$(grep -c '"severity":' "$TMPOUT" 2>/dev/null || true)
        FINDING_COUNT=${FINDING_COUNT:-0}
        if [ "$FINDING_COUNT" -gt 0 ]; then DETECTED="true"; else DETECTED="false"; fi
    else
        # smell_report_multi.sh outputs text format: "N error(s) detected"
        local ERR_COUNT WARN_COUNT
        ERR_COUNT=$(grep -oE '[0-9]+ error\(s\) detected' "$TMPOUT" 2>/dev/null | awk '{sum+=$1} END{print sum+0}')
        WARN_COUNT=$(grep -oE '[0-9]+ warning\(s\) detected' "$TMPOUT" 2>/dev/null | awk '{sum+=$1} END{print sum+0}')
        FINDING_COUNT=$(( ERR_COUNT + WARN_COUNT ))
        if [ "$FINDING_COUNT" -gt 0 ]; then DETECTED="true"; else DETECTED="false"; fi
    fi

    # Build files JSON array
    local FILES_JSON="["
    for i in "${!FILES[@]}"; do
        local BASENAME
        BASENAME=$(basename "${FILES[$i]}")
        [ "$i" -gt 0 ] && FILES_JSON+=","
        FILES_JSON+="\"${BASENAME}\""
    done
    FILES_JSON+="]"

    printf '{"test":"%s","tier":"%s","expected":"%s","files":%s,"detected":%s,"finding_count":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$TIER" "$EXPECTED" "$FILES_JSON" "$DETECTED" "$FINDING_COUNT" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected      : $DETECTED"
    echo "    finding count : $FINDING_COUNT"
    echo "    wall time     : ${WALL_TIME}s"
    echo "    peak RSS      : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# -----------------------------------------------------------------------
# Test cases
# -----------------------------------------------------------------------

echo "=== TIER 1: Smell pattern variants ==="
echo

echo "--- binary_if (Detector 1) ---"
run_case "bad_binary_if_01"    "tier1" "bad"  single "$TESTSUITE/binary_if/bad_binary_if_01.c"
run_case "bad_binary_if_flow02" "tier1" "bad"  single "$TESTSUITE/binary_if/bad_binary_if_flow02.c"
run_case "bad_binary_if_flow05" "tier1" "bad"  single "$TESTSUITE/binary_if/bad_binary_if_flow05.c"
run_case "bad_binary_if_flow11" "tier1" "bad"  single "$TESTSUITE/binary_if/bad_binary_if_flow11.c"
run_case "good_binary_if_01"   "tier1" "good" single "$TESTSUITE/binary_if/good_binary_if_01.c"
echo

echo "--- deref_no_check (Detectors 3 & 4) ---"
run_case "bad_null_deref_01"   "tier1" "bad"  single "$TESTSUITE/deref_no_check/bad_null_deref_01.c"
run_case "good_guarded_01"     "tier1" "good" single "$TESTSUITE/deref_no_check/good_guarded_01.c"
run_case "smell_no_guard_01"   "tier1" "bad"  single "$TESTSUITE/deref_no_check/smell_no_guard_01.c"
echo

echo "--- char (Detectors 3 & 4) ---"
run_case "bad_char_01"         "tier1" "bad"  single "$TESTSUITE/char/bad_char_01.c"
run_case "bad_char_01b"        "tier1" "bad"  single "$TESTSUITE/char/bad_char_01b.c"
run_case "good_char_01"        "tier1" "good" single "$TESTSUITE/char/good_char_01.c"
run_case "smell_char_01b"      "tier1" "bad"  single "$TESTSUITE/char/smell_char_01b.c"
run_case "good_char_01b"       "tier1" "good" single "$TESTSUITE/char/good_char_01b.c"
echo

echo "--- deref_after_check (Detector 5) ---"
run_case "bad_deref_after_check_01" "tier1" "bad" single "$TESTSUITE/after_check/bad_deref_after_check_01.c"
echo

echo "--- check_after_deref (Detector 6) ---"
run_case "bad_check_after_deref_01" "tier1" "bad" single "$TESTSUITE/check_after_deref/bad_check_after_deref_01.c"
echo

# -----------------------------------------------------------------------
echo "=== TIER 2: Context variants ==="
echo

echo "--- interprocedural (Detector 2) ---"
run_case "bad_interprocedural_01"      "tier2" "bad" single "$TESTSUITE/interprocedural/bad_interprocedural_01.c"
run_case "good_interprocedural_01"     "tier2" "bad" single "$TESTSUITE/interprocedural/good_interprocedural_01.c"
run_case "bad_char_interprocedural_01" "tier2" "bad" single "$TESTSUITE/interprocedural/bad_char_interprocedural_01.c"
run_case "bad_char_interprocedural_22" "tier2" "bad" multi \
    "$TESTSUITE/interprocedural/bad_char_interprocedural_22a.c" \
    "$TESTSUITE/interprocedural/bad_char_interprocedural_22b.c"
echo

# -----------------------------------------------------------------------
echo "=== TIER 3: Known limitation cases (expected: missed by SmellDetect) ==="
echo

echo "--- char literal initializer (Detector 4 limitation) ---"
run_case "smell_char_01"             "tier3" "bad" single "$TESTSUITE/char/smell_char_01.c"
echo

echo "--- struct propagation (Detectors 3 & 4 limitations) ---"
run_case "bad_struct_ptr_to_ptr_01"  "tier3" "bad" single "$TESTSUITE/struct/bad_struct_ptr_to_ptr_01.c"
run_case "bad_struct_copy_01"        "tier3" "bad" single "$TESTSUITE/struct/bad_struct_copy_01.c"
run_case "bad_struct_union_01"       "tier3" "bad" single "$TESTSUITE/struct/bad_struct_union_01.c"
echo

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
