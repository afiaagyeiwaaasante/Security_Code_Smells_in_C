#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on each CWE-680 test case and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether buffer size mismatch was detected
# Detection query: malloc calls whose argument is a multiplication expression
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE680"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"

> "$RESULTS"

echo "========================================"
echo " SCS002 — Joern Benchmark"
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
    cat > "$SCALA_SCRIPT" << EOF
importCode("${SOURCE_PATH}")
// Find malloc calls where the argument is a multiplication expression
val hits = cpg.call.name("malloc")
  .where(_.argument.isCall.name("<operator>.multiplication"))
  .l
val detected = hits.nonEmpty
println(s"JOERN_RESULT:\$detected")
EOF

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

# --- Baseline ---
run_case "bad_malloc_01"          "$TESTSUITE/malloc/bad_malloc_01.c"          '["bad_malloc_01.c"]'
run_case "good_malloc_01"         "$TESTSUITE/malloc/good_malloc_01.c"         '["good_malloc_01.c"]'
run_case "good_malloc_01_guarded" "$TESTSUITE/malloc/good_malloc_01_guarded.c" '["good_malloc_01_guarded.c"]'

# --- Fixed data source ---
run_case "bad_malloc_fixed_01"          "$TESTSUITE/malloc/bad_malloc_fixed_01.c"          '["bad_malloc_fixed_01.c"]'
run_case "good_malloc_fixed_01"         "$TESTSUITE/malloc/good_malloc_fixed_01.c"         '["good_malloc_fixed_01.c"]'
run_case "good_malloc_fixed_01_guarded" "$TESTSUITE/malloc/good_malloc_fixed_01_guarded.c" '["good_malloc_fixed_01_guarded.c"]'

# --- fgets data source ---
run_case "bad_malloc_fgets_01"          "$TESTSUITE/malloc/bad_malloc_fgets_01.c"          '["bad_malloc_fgets_01.c"]'
run_case "good_malloc_fgets_01"         "$TESTSUITE/malloc/good_malloc_fgets_01.c"         '["good_malloc_fgets_01.c"]'
run_case "good_malloc_fgets_01_guarded" "$TESTSUITE/malloc/good_malloc_fgets_01_guarded.c" '["good_malloc_fgets_01_guarded.c"]'

# --- rand data source ---
run_case "bad_malloc_rand_01"          "$TESTSUITE/malloc/bad_malloc_rand_01.c"          '["bad_malloc_rand_01.c"]'
run_case "good_malloc_rand_01"         "$TESTSUITE/malloc/good_malloc_rand_01.c"         '["good_malloc_rand_01.c"]'
run_case "good_malloc_rand_01_guarded" "$TESTSUITE/malloc/good_malloc_rand_01_guarded.c" '["good_malloc_rand_01_guarded.c"]'

# --- Precomputed size ---
run_case "bad_malloc_precomputed_01"  "$TESTSUITE/malloc/bad_malloc_precomputed_01.c"  '["bad_malloc_precomputed_01.c"]'
run_case "good_malloc_precomputed_01" "$TESTSUITE/malloc/good_malloc_precomputed_01.c" '["good_malloc_precomputed_01.c"]'

# --- Interprocedural ---
run_case "bad_malloc_return_01"    "$TESTSUITE/interprocedural/bad_malloc_return_01.c"    '["bad_malloc_return_01.c"]'
run_case "good_malloc_interproc_01" "$TESTSUITE/interprocedural/good_malloc_interproc_01.c" '["good_malloc_interproc_01.c"]'

TMPDIR_INTERPROC=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_malloc_interproc_01a.c" "$TMPDIR_INTERPROC/"
cp "$TESTSUITE/interprocedural/bad_malloc_interproc_01b.c" "$TMPDIR_INTERPROC/"
run_case "bad_malloc_interproc_01" "$TMPDIR_INTERPROC" '["bad_malloc_interproc_01a.c","bad_malloc_interproc_01b.c"]'
rm -rf "$TMPDIR_INTERPROC"

# --- Struct member ---
run_case "bad_malloc_struct_01"  "$TESTSUITE/struct/bad_malloc_struct_01.c"  '["bad_malloc_struct_01.c"]'
run_case "good_malloc_struct_01" "$TESTSUITE/struct/good_malloc_struct_01.c" '["good_malloc_struct_01.c"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
