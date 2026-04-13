#!/usr/bin/env bash
# joern/scripts/run_joern.sh
# Runs Joern on each CWE-242 test case and records:
#   - wall-clock time  (includes JVM startup + CPG build + query)
#   - peak RSS (resident set size)
#   - whether gets() was detected
# Output: joern/results/joern_results.json  (one JSON object per line)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TESTSUITE="$PROJECT_ROOT/testsuites/CWE242"
RESULTS="$SCRIPT_DIR/../results/joern_results.json"

> "$RESULTS"   # clear previous results

echo "========================================"
echo " SCS001 — Joern Benchmark"
echo " Output: $RESULTS"
echo " Date  : $(date)"
echo "========================================"
echo

# -----------------------------------------------------------------------
# Helper: run Joern on a source path (file or directory), capture metrics
# -----------------------------------------------------------------------
run_case() {
    local TEST_NAME="$1"
    local SOURCE_PATH="$2"     # file path or temp dir for multi-file
    local FILES_JSON="$3"      # pre-built JSON array string for output

    echo "--- $TEST_NAME ---"

    # Build a temp Scala script that imports the source and queries gets()
    local SCALA_SCRIPT
    SCALA_SCRIPT=$(mktemp /tmp/joern_script_XXXXXX.sc)
    cat > "$SCALA_SCRIPT" << EOF
importCode("${SOURCE_PATH}")
val hits = cpg.call.name("gets").l
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

# -----------------------------------------------------------------------
# Single-file test cases
# -----------------------------------------------------------------------
run_case "bad_gets_01" \
    "$TESTSUITE/gets/bad_gets_01.c" \
    '["bad_gets_01.c"]'

run_case "good_gets_01" \
    "$TESTSUITE/gets/good_gets_01.c" \
    '["good_gets_01.c"]'

# -----------------------------------------------------------------------
# Multi-file interprocedural case
# Joern's importCode on a directory builds a cross-file CPG — this is
# where Joern has an advantage over single-file tools.
# -----------------------------------------------------------------------
TMPDIR_INTERPROC=$(mktemp -d /tmp/joern_interproc_XXXXXX)
cp "$TESTSUITE/interprocedural/bad_gets_interprocedural_62a.c" "$TMPDIR_INTERPROC/"
cp "$TESTSUITE/interprocedural/bad_gets_interprocedural_62b.c" "$TMPDIR_INTERPROC/"
cp -r "$TESTSUITE/testsuitesupport" "$TMPDIR_INTERPROC/" 2>/dev/null || true

run_case "bad_gets_interprocedural_62" \
    "$TMPDIR_INTERPROC" \
    '["bad_gets_interprocedural_62a.c","bad_gets_interprocedural_62b.c"]'

rm -rf "$TMPDIR_INTERPROC"

# -----------------------------------------------------------------------
# Multi-instance test cases
# -----------------------------------------------------------------------
run_case "bad_gets_multi_01" \
    "$TESTSUITE/multi/bad_gets_multi_01.c" \
    '["bad_gets_multi_01.c"]'

run_case "bad_gets_multi_02" \
    "$TESTSUITE/multi/bad_gets_multi_02.c" \
    '["bad_gets_multi_02.c"]'

run_case "bad_gets_mixed_01" \
    "$TESTSUITE/multi/bad_gets_mixed_01.c" \
    '["bad_gets_mixed_01.c"]'

echo "========================================"
echo " Results saved to: $RESULTS"
echo "========================================"
