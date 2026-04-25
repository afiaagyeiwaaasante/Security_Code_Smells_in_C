#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on each CWE-259 test case and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether a hardcoded credential smell was detected
#
# Detection queries:
#   1. Variable declarations where name matches credential keywords and
#      the initialiser is a string literal.
#   2. strcmp/strncmp calls where one argument is a string literal.
#
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE259"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"
mkdir -p "$(dirname "$RESULTS")"

> "$RESULTS"

echo "========================================"
echo " SCS010 — Joern Benchmark"
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

val credPat = "(?i)(password|passwd|pwd|secret|api.?key|token|credential|passphrase|private.?key)".r

// 1. Local variables with credential name initialised to a string literal
val varLiteral = cpg.local
  .filter(l => credPat.findFirstIn(l.name).isDefined)
  .filter { l =>
    val assigns = cpg.assignment
      .filter(a => a.target.code == l.name)
      .argument.order(2)
      .isLiteral.l
    assigns.nonEmpty
  }

// 2. strcmp/strncmp with a string literal as any argument
val strcmpHard = cpg.call
  .nameExact("strcmp", "strncmp")
  .filter { c =>
    c.argument.isLiteral.nonEmpty
  }

val detected = (varLiteral.l ++ strcmpHard.l).nonEmpty
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

run_case "bad_password_var_01"  "tier1" "bad"  "$TESTSUITE/password_var/bad_password_var_01.c"  '["bad_password_var_01.c"]'
run_case "good_password_var_01" "tier1" "good" "$TESTSUITE/password_var/good_password_var_01.c" '["good_password_var_01.c"]'

run_case "bad_define_const_01"  "tier1" "bad"  "$TESTSUITE/define_const/bad_define_const_01.c"  '["bad_define_const_01.c"]'
run_case "good_define_const_01" "tier1" "good" "$TESTSUITE/define_const/good_define_const_01.c" '["good_define_const_01.c"]'

run_case "bad_strcmp_auth_01"  "tier1" "bad"  "$TESTSUITE/strcmp_auth/bad_strcmp_auth_01.c"  '["bad_strcmp_auth_01.c"]'
run_case "good_strcmp_auth_01" "tier1" "good" "$TESTSUITE/strcmp_auth/good_strcmp_auth_01.c" '["good_strcmp_auth_01.c"]'

# =======================================================================
# TIER 2 — Context variants
# =======================================================================
echo "=== TIER 2: Context variants ==="
echo

run_case "bad_password_interprocedural_22a"  "tier2" "bad"  "$TESTSUITE/interprocedural/bad_password_interprocedural_22a.c"  '["bad_password_interprocedural_22a.c"]'
run_case "good_password_interprocedural_22b" "tier2" "good" "$TESTSUITE/interprocedural/good_password_interprocedural_22b.c" '["good_password_interprocedural_22b.c"]'

run_case "bad_password_class_84"  "tier2" "bad"  "$TESTSUITE/cpp_class/bad_password_class_84.cpp"  '["bad_password_class_84.cpp"]'
run_case "good_password_class_84" "tier2" "good" "$TESTSUITE/cpp_class/good_password_class_84.cpp" '["good_password_class_84.cpp"]'

# =======================================================================
# TIER 3 — Known limitation cases (interprocedural sink-only)
# =======================================================================
echo "=== TIER 3: Known limitation cases (interprocedural sink-only) ==="
echo

run_case "bad_password_interprocedural_22b" "tier3" "bad" "$TESTSUITE/interprocedural/bad_password_interprocedural_22b.c" '["bad_password_interprocedural_22b.c"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
