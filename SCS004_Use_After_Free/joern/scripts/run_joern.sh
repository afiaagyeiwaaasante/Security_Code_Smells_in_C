#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on representative CWE-416 test cases and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a use-after-free smell was detected
#
# Detection query:
#   free/delete call followed by a use of the same identifier in the same function.
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE416"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS004 — Joern Benchmark"
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
// Find free/delete calls, then check if the freed variable is used after
val freedVars = cpg.call.name("free", "delete", "<operator>.delete")
  .argument(1).isIdentifier.name.toSet
// Look for any use of those variables after a free/delete call
val hits = cpg.identifier
  .filter(i => freedVars.contains(i.name))
  .inCall
  .nameNot("free", "delete", "<operator>.delete")
  .l
val detected = hits.nonEmpty
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

# Detector 1 — use_after_free (malloc/free)
run_case "bad_use_after_free_int_01"  "$TESTSUITE/int/bad_use_after_free_int_01.c"  '["bad_use_after_free_int_01.c"]'
run_case "good_use_after_free_int_01" "$TESTSUITE/int/good_use_after_free_int_01.c" '["good_use_after_free_int_01.c"]'

# Detector 4 — new_delete_uaf (C++ new/delete)
run_case "bad_new_delete_int_01"  "$TESTSUITE/new_delete_int/bad_new_delete_int_01.cpp"  '["bad_new_delete_int_01.cpp"]'
run_case "good_new_delete_int_01" "$TESTSUITE/new_delete_int/good_new_delete_int_01.cpp" '["good_new_delete_int_01.cpp"]'

# Detector 6 — return_freed_ptr
run_case "bad_return_freed_ptr_01"  "$TESTSUITE/freed_pointer/bad_return_freed_ptr_01.c"  '["bad_return_freed_ptr_01.c"]'
run_case "good_return_freed_ptr_01" "$TESTSUITE/freed_pointer/good_return_freed_ptr_01.c" '["good_return_freed_ptr_01.c"]'

# Detector 7 — operator_equals_uaf
run_case "bad_operator_equals_01"  "$TESTSUITE/operator_equals/bad_operator_equals_01.cpp"  '["bad_operator_equals_01.cpp"]'
run_case "good_operator_equals_01" "$TESTSUITE/operator_equals/good_operator_equals_01.cpp" '["good_operator_equals_01.cpp"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
