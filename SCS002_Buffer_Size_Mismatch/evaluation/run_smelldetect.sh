#!/usr/bin/env bash
# evaluation/run_smelldetect.sh
# Runs our SCS002 tool on each CWE-680 test case and records:
#   - wall-clock time
#   - peak RSS (resident set size)
#   - whether a finding was detected
# Output: evaluation/smelldetect_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$PROJECT_ROOT/src"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE680"
RESULTS="$SCRIPT_DIR/smelldetect_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS002 — SmellDetect Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local FILE="$2"

    echo "--- $TEST_NAME ---"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/smelldetect_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/smelldetect_time_XXXXXX)

    /usr/bin/time -l bash "$SRC_DIR/smell_report.sh" "$FILE" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    if grep -q '"severity":' "$TMPOUT" 2>/dev/null; then
        DETECTED="true"
    else
        DETECTED="false"
    fi

    printf '{"test":"%s","files":["%s"],"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$(basename "$FILE")" "$DETECTED" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected  : $DETECTED"
    echo "    wall time : ${WALL_TIME}s"
    echo "    peak RSS  : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$TMPOUT" "$TIMEFILE"
}

# --- Baseline ---
run_case "bad_malloc_01"          "$TESTSUITE/malloc/bad_malloc_01.c"
run_case "good_malloc_01"         "$TESTSUITE/malloc/good_malloc_01.c"
run_case "good_malloc_01_guarded" "$TESTSUITE/malloc/good_malloc_01_guarded.c"

# --- Fixed data source ---
run_case "bad_malloc_fixed_01"          "$TESTSUITE/malloc/bad_malloc_fixed_01.c"
run_case "good_malloc_fixed_01"         "$TESTSUITE/malloc/good_malloc_fixed_01.c"
run_case "good_malloc_fixed_01_guarded" "$TESTSUITE/malloc/good_malloc_fixed_01_guarded.c"

# --- fgets data source ---
run_case "bad_malloc_fgets_01"          "$TESTSUITE/malloc/bad_malloc_fgets_01.c"
run_case "good_malloc_fgets_01"         "$TESTSUITE/malloc/good_malloc_fgets_01.c"
run_case "good_malloc_fgets_01_guarded" "$TESTSUITE/malloc/good_malloc_fgets_01_guarded.c"

# --- rand data source ---
run_case "bad_malloc_rand_01"          "$TESTSUITE/malloc/bad_malloc_rand_01.c"
run_case "good_malloc_rand_01"         "$TESTSUITE/malloc/good_malloc_rand_01.c"
run_case "good_malloc_rand_01_guarded" "$TESTSUITE/malloc/good_malloc_rand_01_guarded.c"

# --- Precomputed size (detect_precomputed_size detector) ---
run_case "bad_malloc_precomputed_01"      "$TESTSUITE/malloc/bad_malloc_precomputed_01.c"
run_case "good_malloc_precomputed_01"     "$TESTSUITE/malloc/good_malloc_precomputed_01.c"

# --- Interprocedural ---
run_case "bad_malloc_return_01"     "$TESTSUITE/interprocedural/bad_malloc_return_01.c"
run_case "good_malloc_interproc_01" "$TESTSUITE/interprocedural/good_malloc_interproc_01.c"

TMPOUT_MULTI=$(mktemp /tmp/smelldetect_out_XXXXXX)
TIMEFILE_MULTI=$(mktemp /tmp/smelldetect_time_XXXXXX)
echo "--- bad_malloc_interproc_01 ---"
/usr/bin/time -l bash "$SRC_DIR/smell_report_multi.sh" \
    "$TESTSUITE/interprocedural/bad_malloc_interproc_01a.c" \
    "$TESTSUITE/interprocedural/bad_malloc_interproc_01b.c" \
    > "$TMPOUT_MULTI" 2>"$TIMEFILE_MULTI" || true
WALL_TIME_M=$(grep real "$TIMEFILE_MULTI" | awk '{print $1}')
PEAK_RSS_M=$(grep "maximum resident set size" "$TIMEFILE_MULTI" | awk '{print $1}')
PEAK_RSS_KB_M=$(( PEAK_RSS_M / 1024 ))
if grep -q '"severity":' "$TMPOUT_MULTI" 2>/dev/null; then DET_M="true"; else DET_M="false"; fi
printf '{"test":"bad_malloc_interproc_01","files":["bad_malloc_interproc_01a.c","bad_malloc_interproc_01b.c"],"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
    "$DET_M" "$WALL_TIME_M" "$PEAK_RSS_KB_M" >> "$RESULTS"
echo "    detected  : $DET_M"
echo "    wall time : ${WALL_TIME_M}s"
echo "    peak RSS  : ${PEAK_RSS_KB_M} KB"
echo
rm -f "$TMPOUT_MULTI" "$TIMEFILE_MULTI"

# --- Struct member (FN case — detector limitation) ---
run_case "bad_malloc_struct_01"  "$TESTSUITE/struct/bad_malloc_struct_01.c"
run_case "good_malloc_struct_01" "$TESTSUITE/struct/good_malloc_struct_01.c"

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
