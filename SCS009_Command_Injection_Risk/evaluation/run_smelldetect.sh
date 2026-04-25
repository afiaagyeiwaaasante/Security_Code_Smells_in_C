#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS009 tool on each CWE-78 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
#
# Note: all SCS009 findings are error/vulnerability (tainted input to system/popen/execl).
#       No smell_ variants exist for this detector.
# Note: interprocedural 22a file (tier3) contains only the taint source with no
#       sink call; single-file analysis cannot detect the pattern there.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE78"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

SMELL_REPORT="$SRC_DIR/smell_report.sh"

> "$RESULTS"

echo "========================================"
echo " SCS009 — SmellDetect Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local TIER="$2"
    local EXPECTED="$3"
    local FILE="$4"

    echo "--- [$TIER] $TEST_NAME (expected: $EXPECTED) ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/smelldetect_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/smelldetect_time_XXXXXX)

    /usr/bin/time -l bash "$SMELL_REPORT" "$FILE" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    local FINDING_COUNT DETECTED
    FINDING_COUNT=$(grep -c '"severity":' "$TMPOUT" 2>/dev/null || true)
    FINDING_COUNT=${FINDING_COUNT:-0}
    if [ "$FINDING_COUNT" -gt 0 ]; then DETECTED="true"; else DETECTED="false"; fi

    printf '{"test":"%s","tier":"%s","expected":"%s","files":["%s"],"detected":%s,"finding_count":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$TIER" "$EXPECTED" "$(basename "$FILE")" \
        "$DETECTED" "$FINDING_COUNT" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected      : $DETECTED"
    echo "    finding count : $FINDING_COUNT"
    echo "    wall time     : ${WALL_TIME}s"
    echo "    peak RSS      : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# -----------------------------------------------------------------------
echo "=== TIER 1: Smell pattern variants ==="
echo

echo "--- Detector 1: system_console ---"
run_case "bad_system_console_01"  "tier1" "bad"  "$TESTSUITE/system_console/bad_system_console_01.c"
run_case "good_system_console_01" "tier1" "good" "$TESTSUITE/system_console/good_system_console_01.c"
echo

echo "--- Detector 2: system_env ---"
run_case "bad_system_env_01"  "tier1" "bad"  "$TESTSUITE/system_env/bad_system_env_01.c"
run_case "good_system_env_01" "tier1" "good" "$TESTSUITE/system_env/good_system_env_01.c"
echo

echo "--- Detector 3: popen_console ---"
run_case "bad_popen_console_01"  "tier1" "bad"  "$TESTSUITE/popen_console/bad_popen_console_01.c"
run_case "good_popen_console_01" "tier1" "good" "$TESTSUITE/popen_console/good_popen_console_01.c"
echo

echo "--- Detector 4: execl_console ---"
run_case "bad_execl_console_01"  "tier1" "bad"  "$TESTSUITE/execl_console/bad_execl_console_01.c"
run_case "good_execl_console_01" "tier1" "good" "$TESTSUITE/execl_console/good_execl_console_01.c"
echo

# -----------------------------------------------------------------------
echo "=== TIER 2: Context variants ==="
echo

echo "--- Interprocedural (sink-side) ---"
run_case "bad_system_interprocedural_22b"  "tier2" "bad"  "$TESTSUITE/interprocedural/bad_system_interprocedural_22b.c"
run_case "good_system_interprocedural_22b" "tier2" "good" "$TESTSUITE/interprocedural/good_system_interprocedural_22b.c"
echo

echo "--- C++ class variant ---"
run_case "bad_system_class_84"  "tier2" "bad"  "$TESTSUITE/cpp_class/bad_system_class_84.cpp"
run_case "good_system_class_84" "tier2" "good" "$TESTSUITE/cpp_class/good_system_class_84.cpp"
echo

# -----------------------------------------------------------------------
echo "=== TIER 3: Known limitation cases (interprocedural source-only) ==="
echo "    (22a file contains only the taint source — no sink call present;"
echo "     single-file analysis cannot detect the pattern)"
echo

run_case "bad_system_interprocedural_22a" "tier3" "bad" "$TESTSUITE/interprocedural/bad_system_interprocedural_22a.c"
echo

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
