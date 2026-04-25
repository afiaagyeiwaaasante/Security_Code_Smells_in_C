#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on each CWE-78 test case and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a command injection smell was detected
#
# Detection query:
#   Find calls to system/popen/execl/execlp where any argument is NOT
#   a string literal.  In the Joern CPG, a string literal appears as a
#   Literal node; a variable appears as an Identifier node.
#   system/popen: command = argument at index 0 (order 1)
#   execl/execlp: path    = argument at index 0 (order 1)
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE78"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS009 — Joern Benchmark"
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

// system/popen: command argument at order 1 must NOT be a variable identifier
val systemPopenBad = cpg.call
  .nameExact("system", "popen")
  .filter { c =>
    val arg = c.argument.order(1).l
    arg.nonEmpty && !arg.exists(_.isLiteral)
  }

// execl/execlp: path argument at order 1 must NOT be a variable identifier
val execlBad = cpg.call
  .nameExact("execl", "execlp")
  .filter { c =>
    val arg = c.argument.order(1).l
    arg.nonEmpty && !arg.exists(_.isLiteral)
  }

val detected = (systemPopenBad.l ++ execlBad.l).nonEmpty
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

run_case "bad_system_console_01"  "tier1" "bad"  "$TESTSUITE/system_console/bad_system_console_01.c"  '["bad_system_console_01.c"]'
run_case "good_system_console_01" "tier1" "good" "$TESTSUITE/system_console/good_system_console_01.c" '["good_system_console_01.c"]'

run_case "bad_system_env_01"  "tier1" "bad"  "$TESTSUITE/system_env/bad_system_env_01.c"  '["bad_system_env_01.c"]'
run_case "good_system_env_01" "tier1" "good" "$TESTSUITE/system_env/good_system_env_01.c" '["good_system_env_01.c"]'

run_case "bad_popen_console_01"  "tier1" "bad"  "$TESTSUITE/popen_console/bad_popen_console_01.c"  '["bad_popen_console_01.c"]'
run_case "good_popen_console_01" "tier1" "good" "$TESTSUITE/popen_console/good_popen_console_01.c" '["good_popen_console_01.c"]'

run_case "bad_execl_console_01"  "tier1" "bad"  "$TESTSUITE/execl_console/bad_execl_console_01.c"  '["bad_execl_console_01.c"]'
run_case "good_execl_console_01" "tier1" "good" "$TESTSUITE/execl_console/good_execl_console_01.c" '["good_execl_console_01.c"]'

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_system_interprocedural_22b"  "tier2" "bad"  "$TESTSUITE/interprocedural/bad_system_interprocedural_22b.c"  '["bad_system_interprocedural_22b.c"]'
run_case "good_system_interprocedural_22b" "tier2" "good" "$TESTSUITE/interprocedural/good_system_interprocedural_22b.c" '["good_system_interprocedural_22b.c"]'

run_case "bad_system_class_84"  "tier2" "bad"  "$TESTSUITE/cpp_class/bad_system_class_84.cpp"  '["bad_system_class_84.cpp"]'
run_case "good_system_class_84" "tier2" "good" "$TESTSUITE/cpp_class/good_system_class_84.cpp" '["good_system_class_84.cpp"]'

# =======================================================================
# TIER 3 — Known limitation cases (interprocedural source-only)
# =======================================================================
echo "=== TIER 3: Known limitation cases (interprocedural source-only) ==="
echo

run_case "bad_system_interprocedural_22a" "tier3" "bad" "$TESTSUITE/interprocedural/bad_system_interprocedural_22a.c" '["bad_system_interprocedural_22a.c"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
