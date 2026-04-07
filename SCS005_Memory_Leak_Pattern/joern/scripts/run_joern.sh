#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on representative CWE-401 test cases and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a memory-leak smell was detected
#
# Detection query:
#   Find malloc() calls whose LHS variable is never passed to free()
#   in the same method.
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE401"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS005 — Joern Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local SOURCE_PATH="$2"
    local FILES_JSON="$3"

    echo "--- $TEST_NAME ---"

    local SCALA_SCRIPT
    SCALA_SCRIPT=$(mktemp /tmp/joern_script_XXXXXX.sc)
    cat > "$SCALA_SCRIPT" << 'SCALAEOF'
importCode("SOURCE_PATH_PLACEHOLDER")
// Find variables assigned via malloc()
val mallocVars = cpg.call.name("malloc", "calloc", "realloc")
  .inAssignment
  .target
  .isIdentifier
  .name
  .toSet
// Find variables passed to free()
val freedVars = cpg.call.name("free")
  .argument(1)
  .isIdentifier
  .name
  .toSet
// Leaked = allocated but never freed
val leaked = mallocVars -- freedVars
val detected = leaked.nonEmpty
println(s"JOERN_RESULT:$detected")
SCALAEOF

    sed -i '' "s|SOURCE_PATH_PLACEHOLDER|${SOURCE_PATH}|g" "$SCALA_SCRIPT"

    local TMPOUT TIMEFILE
    TMPOUT=$(mktemp /tmp/joern_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/joern_time_XXXXXX)

    /usr/bin/time -l joern --script "$SCALA_SCRIPT" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    if grep -q "JOERN_RESULT:true" "$TMPOUT" 2>/dev/null; then
        DETECTED="true"
    else
        DETECTED="false"
    fi

    printf '{"test":"%s","files":%s,"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$FILES_JSON" "$DETECTED" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected  : $DETECTED"
    echo "    wall time : ${WALL_TIME}s"
    echo "    peak RSS  : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$SCALA_SCRIPT" "$TMPOUT" "$TIMEFILE"
}

# Detector 1 — no_free_on_exit
run_case "bad_malloc_no_free_01"    "$TESTSUITE/int/bad_malloc_no_free_01.c"    '["bad_malloc_no_free_01.c"]'
run_case "good_malloc_with_free_01" "$TESTSUITE/int/good_malloc_with_free_01.c" '["good_malloc_with_free_01.c"]'

# Detector 1 — early_return variant
run_case "bad_early_return_01"  "$TESTSUITE/early_return/bad_early_return_01.c"  '["bad_early_return_01.c"]'
run_case "good_early_return_01" "$TESTSUITE/early_return/good_early_return_01.c" '["good_early_return_01.c"]'

# Detector 2 — overwrite_leak
run_case "bad_overwrite_01"  "$TESTSUITE/overwrite/bad_overwrite_01.c"  '["bad_overwrite_01.c"]'
run_case "good_overwrite_01" "$TESTSUITE/overwrite/good_overwrite_01.c" '["good_overwrite_01.c"]'

# Detector 3 — new_no_delete
run_case "bad_new_no_delete_01"  "$TESTSUITE/new_delete/bad_new_no_delete_01.cpp"  '["bad_new_no_delete_01.cpp"]'
run_case "good_new_delete_01"    "$TESTSUITE/new_delete/good_new_delete_01.cpp"    '["good_new_delete_01.cpp"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
