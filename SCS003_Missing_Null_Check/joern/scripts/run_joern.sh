#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on representative CWE-476 test cases and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a null pointer smell was detected
#
# Detection query:
#   Looks for indirectFieldAccess or indirectIndexAccess calls where the
#   receiver was assigned NULL (literal 0) in the same function.
#   Also detects bitwise & in pointer-check conditions (binary_if pattern).
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE476"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS003 — Joern Benchmark"
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
// Pattern 1: ptr = NULL then ptr->field or ptr[idx]
val nullPtrs = cpg.assignment
  .where(_.source.isLiteral.codeExact("0"))
  .target.isIdentifier.name.toSet
val derefHits = cpg.call
  .name("<operator>.indirectFieldAccess", "<operator>.indirectIndexAccess")
  .argument(1).isIdentifier
  .filter(i => nullPtrs.contains(i.name))
  .l
// Pattern 2: bitwise & used in condition with pointer comparison (binary_if)
val bitwiseHits = cpg.call.name("<operator>.and")
  .where(_.argument.isCall.name("<operator>.notEquals", "<operator>.equals"))
  .l
val detected = derefHits.nonEmpty || bitwiseHits.nonEmpty
println(s"JOERN_RESULT:$detected")
SCALAEOF

    # Substitute the actual source path
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

# Detector 1 — binary_if
run_case "bad_binary_if_01"  "$TESTSUITE/binary_if/bad_binary_if_01.c"  '["bad_binary_if_01.c"]'
run_case "good_binary_if_01" "$TESTSUITE/binary_if/good_binary_if_01.c" '["good_binary_if_01.c"]'

# Detector 3 — null_deref
run_case "bad_null_deref_01" "$TESTSUITE/deref_no_check/bad_null_deref_01.c" '["bad_null_deref_01.c"]'
run_case "good_guarded_01"   "$TESTSUITE/deref_no_check/good_guarded_01.c"   '["good_guarded_01.c"]'

# Detector 2 — interprocedural (single-file)
run_case "bad_interprocedural_01"  "$TESTSUITE/interprocedural/bad_interprocedural_01.c"  '["bad_interprocedural_01.c"]'
run_case "good_interprocedural_01" "$TESTSUITE/interprocedural/good_interprocedural_01.c" '["good_interprocedural_01.c"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
