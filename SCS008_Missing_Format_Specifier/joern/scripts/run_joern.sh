#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on each CWE-134 test case and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a missing format specifier smell was detected
#
# Detection query:
#   Find calls to printf/fprintf/vprintf/vfprintf/syslog where the format
#   argument is NOT a string literal.  In the Joern CPG, a string literal
#   appears as a Literal node; a variable appears as an Identifier node.
#   printf/vprintf: format = argument at index 0 (order 1)
#   fprintf/vfprintf/syslog: format = argument at index 1 (order 2)
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE134"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS008 — Joern Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

run_case() {
    local TEST_NAME="$1"
    local TIER="$2"
    local EXPECTED="$3"
    local SOURCE_PATH="$4"
    local FILES_JSON="$5"

    echo "--- [$TIER] $TEST_NAME (expected: $EXPECTED) ---"

    local SCALA_SCRIPT TMPOUT TIMEFILE
    SCALA_SCRIPT=$(mktemp /tmp/joern_script_XXXXXX.sc)
    TMPOUT=$(mktemp /tmp/joern_out_XXXXXX)
    TIMEFILE=$(mktemp /tmp/joern_time_XXXXXX)

    cat > "$SCALA_SCRIPT" << 'SCALAEOF'
importCode("SOURCE_PATH_PLACEHOLDER")

// printf/vprintf: format is argument at index 0 (order 1) — must be a Literal
val printfBad = cpg.call
  .nameExact("printf", "vprintf")
  .filter { c =>
    val fmt = c.argument.order(1).l
    fmt.nonEmpty && !fmt.exists(_.isLiteral)
  }

// fprintf/vfprintf/syslog: format is argument at index 1 (order 2) — must be a Literal
val fprintfBad = cpg.call
  .nameExact("fprintf", "vfprintf", "syslog")
  .filter { c =>
    val fmt = c.argument.order(2).l
    fmt.nonEmpty && !fmt.exists(_.isLiteral)
  }

val detected = (printfBad.l ++ fprintfBad.l).nonEmpty
println(s"JOERN_RESULT:$detected")
SCALAEOF

    sed -i '' "s|SOURCE_PATH_PLACEHOLDER|${SOURCE_PATH}|g" "$SCALA_SCRIPT"

    /usr/bin/time -l joern --script "$SCALA_SCRIPT" \
        > "$TMPOUT" 2>"$TIMEFILE" || true

    local WALL_TIME PEAK_RSS_BYTES PEAK_RSS_KB DETECTED
    WALL_TIME=$(grep real "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_BYTES=$(grep "maximum resident set size" "$TIMEFILE" | awk '{print $1}')
    PEAK_RSS_KB=$(( PEAK_RSS_BYTES / 1024 ))

    if grep -q 'JOERN_RESULT:true' "$TMPOUT" 2>/dev/null; then
        DETECTED="true"
    else
        DETECTED="false"
    fi

    printf '{"test":"%s","tier":"%s","expected":"%s","files":%s,"detected":%s,"wall_time_s":%s,"peak_rss_kb":%s}\n' \
        "$TEST_NAME" "$TIER" "$EXPECTED" "$FILES_JSON" "$DETECTED" "$WALL_TIME" "$PEAK_RSS_KB" \
        >> "$RESULTS"

    echo "    detected  : $DETECTED"
    echo "    wall time : ${WALL_TIME}s"
    echo "    peak RSS  : ${PEAK_RSS_KB} KB"
    echo

    rm -f "$SCALA_SCRIPT" "$TMPOUT" "$TIMEFILE"
}

# =======================================================================
# TIER 1 — Smell pattern variants
# =======================================================================
echo "=== TIER 1: Smell pattern variants ==="
echo

run_case "bad_printf_direct_01"  "tier1" "bad"  "$TESTSUITE/printf_direct/bad_printf_direct_01.c"  '["bad_printf_direct_01.c"]'
run_case "good_printf_direct_01" "tier1" "good" "$TESTSUITE/printf_direct/good_printf_direct_01.c" '["good_printf_direct_01.c"]'

run_case "bad_fprintf_direct_01"  "tier1" "bad"  "$TESTSUITE/fprintf_direct/bad_fprintf_direct_01.c"  '["bad_fprintf_direct_01.c"]'
run_case "good_fprintf_direct_01" "tier1" "good" "$TESTSUITE/fprintf_direct/good_fprintf_direct_01.c" '["good_fprintf_direct_01.c"]'

run_case "bad_env_format_01"  "tier1" "bad"  "$TESTSUITE/env_format/bad_env_format_01.c"  '["bad_env_format_01.c"]'
run_case "good_env_format_01" "tier1" "good" "$TESTSUITE/env_format/good_env_format_01.c" '["good_env_format_01.c"]'

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_printf_interprocedural_22b"  "tier2" "bad"  "$TESTSUITE/interprocedural/bad_printf_interprocedural_22b.c"  '["bad_printf_interprocedural_22b.c"]'
run_case "good_printf_interprocedural_22b" "tier2" "good" "$TESTSUITE/interprocedural/good_printf_interprocedural_22b.c" '["good_printf_interprocedural_22b.c"]'

run_case "bad_printf_class_84"  "tier2" "bad"  "$TESTSUITE/cpp_class/bad_printf_class_84.cpp"  '["bad_printf_class_84.cpp"]'
run_case "good_printf_class_84" "tier2" "good" "$TESTSUITE/cpp_class/good_printf_class_84.cpp" '["good_printf_class_84.cpp"]'

# =======================================================================
# TIER 3 — Known limitation cases (interprocedural source-only)
# =======================================================================
echo "=== TIER 3: Known limitation cases (interprocedural source-only) ==="
echo

run_case "bad_printf_interprocedural_22a"  "tier3" "bad"  "$TESTSUITE/interprocedural/bad_printf_interprocedural_22a.c"  '["bad_printf_interprocedural_22a.c"]'
run_case "good_printf_interprocedural_22a" "tier3" "good" "$TESTSUITE/interprocedural/good_printf_interprocedural_22a.c" '["good_printf_interprocedural_22a.c"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
