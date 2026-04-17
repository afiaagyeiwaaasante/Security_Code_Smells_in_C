#!/usr/bin/env bash
# shared/bin/scan_subsystem.sh
#
# Batch SmellDetect scan over a directory of C/C++ source files.
# Runs smell_report.sh on every file individually, and smell_report_multi.sh
# (per subdirectory group) when available for the chosen SCS detector.
# Aggregates all findings into summary.txt and findings_all.json.
#
# Usage:
#   bash shared/bin/scan_subsystem.sh --dir <path> --scs <IDs> [options]
#
# Options:
#   --dir   <path>   Directory to scan recursively          (required)
#   --scs   <list>   Comma-separated SCS IDs or "all"       (required)
#   --out   <path>   Output root (default: scan_<name>_<ts> next to this script)
#   --jobs  <n>      Parallel workers for single-file pass  (default: 1)
#   --ext   <list>   Comma-separated file extensions        (default: c)
#   --limit <n>      Cap number of files scanned; 0 = no cap (default: 0)
#
# Output layout:
#   <out>/
#   ├── <SCS_ID>/            one subdir per source file (named by relative path)
#   │   └── <rel_path>/
#   │       ├── <base>_findings_<ts>.json
#   │       └── stdout.log
#   ├── multi/               smell_report_multi.sh results, grouped by subdir
#   │   └── <SCS_ID>/
#   │       └── <subdir>/
#   │           ├── combined_findings_<ts>.json
#   │           └── stdout.log
#   ├── findings_all.json    every finding from all SCS combined (JSON array)
#   └── summary.txt          human-readable report
#
# Examples:
#   # Run SCS006 + SCS007 over linux/net, 4 parallel workers
#   bash shared/bin/scan_subsystem.sh \
#       --dir linux/net --scs SCS006,SCS007 --out results/net_scan --jobs 4
#
#   # Quick pilot: first 50 files, single SCS
#   bash shared/bin/scan_subsystem.sh \
#       --dir linux/net/ipv4 --scs SCS006 --limit 50

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── defaults ──────────────────────────────────────────────────────────────────
TARGET_DIR=""
SCS_LIST=""
OUT_DIR=""
JOBS=1
EXTENSIONS="c"
LIMIT=0

# ── argument parsing ──────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --dir)   TARGET_DIR="$2"; shift 2 ;;
        --scs)   SCS_LIST="$2";   shift 2 ;;
        --out)   OUT_DIR="$2";    shift 2 ;;
        --jobs)  JOBS="$2";       shift 2 ;;
        --ext)   EXTENSIONS="$2"; shift 2 ;;
        --limit) LIMIT="$2";      shift 2 ;;
        -h|--help)
            sed -n '2,/^set /p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$TARGET_DIR" ] || [ -z "$SCS_LIST" ]; then
    echo "Usage: bash scan_subsystem.sh --dir <path> --scs <SCS006,SCS007,...|all> [options]" >&2
    exit 1
fi

TARGET_DIR=$(cd "$TARGET_DIR" && pwd)
SUBSYSTEM=$(basename "$TARGET_DIR")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/scan_${SUBSYSTEM}_${TIMESTAMP}}"
mkdir -p "$OUT_DIR"

# ── resolve SCS list ──────────────────────────────────────────────────────────
if [ "$SCS_LIST" = "all" ]; then
    SCS_LIST="SCS001,SCS002,SCS003,SCS004,SCS005,SCS006,SCS007,SCS008,SCS009,SCS010"
fi

# Parallel indexed arrays (bash 3.2 compatible — no declare -A)
VALID_SCS=()
SINGLE_PATHS=()
MULTI_PATHS=()   # empty string means no multi script

IFS=',' read -ra RAW_IDS <<< "$SCS_LIST"
for SCS_ID in "${RAW_IDS[@]}"; do
    SCS_DIR=$(ls -d "$REPO_ROOT/${SCS_ID}_"* 2>/dev/null | head -1)
    if [ -z "$SCS_DIR" ]; then
        echo "WARNING: $SCS_ID — directory not found, skipping" >&2; continue
    fi
    SINGLE="$SCS_DIR/src/smell_report.sh"
    MULTI="$SCS_DIR/src/smell_report_multi.sh"
    if [ ! -f "$SINGLE" ]; then
        echo "WARNING: $SCS_ID — smell_report.sh not found, skipping" >&2; continue
    fi
    VALID_SCS+=("$SCS_ID")
    SINGLE_PATHS+=("$SINGLE")
    if [ -f "$MULTI" ]; then
        MULTI_PATHS+=("$MULTI")
    else
        MULTI_PATHS+=("")
    fi
done

if [ ${#VALID_SCS[@]} -eq 0 ]; then
    echo "ERROR: no valid SCS detectors found" >&2; exit 1
fi

# Build display strings
SINGLE_IDS=""
MULTI_IDS=""
for i in $(seq 0 $((${#VALID_SCS[@]} - 1))); do
    SINGLE_IDS="$SINGLE_IDS ${VALID_SCS[$i]}"
    [ -n "${MULTI_PATHS[$i]}" ] && MULTI_IDS="$MULTI_IDS ${VALID_SCS[$i]}"
done
SINGLE_IDS="${SINGLE_IDS# }"
MULTI_IDS="${MULTI_IDS:-  (none)}"

# ── discover source files ─────────────────────────────────────────────────────
# bash 3.2 compatible: use while-read instead of mapfile
ALL_FILES=()
IFS=',' read -ra EXTS <<< "$EXTENSIONS"
while IFS= read -r f; do
    ALL_FILES+=("$f")
done < <(
    for ext in "${EXTS[@]}"; do
        find "$TARGET_DIR" -name "*.${ext}" -type f
    done | sort
)

TOTAL=${#ALL_FILES[@]}
if [ "$LIMIT" -gt 0 ] && [ "$TOTAL" -gt "$LIMIT" ]; then
    # trim array to LIMIT entries
    TOTAL=$LIMIT
fi

echo "════════════════════════════════════════════════════════════"
echo " SmellDetect — Subsystem Scan"
echo " Target      : $TARGET_DIR"
echo " SCS (single): $SINGLE_IDS"
echo " SCS (multi) : $MULTI_IDS"
echo " Files       : $TOTAL"
echo " Jobs        : $JOBS"
echo " Output      : $OUT_DIR"
echo " Date        : $(date)"
echo "════════════════════════════════════════════════════════════"
echo

# ── single-file pass ──────────────────────────────────────────────────────────
for i in $(seq 0 $((${#VALID_SCS[@]} - 1))); do
    SCS_ID="${VALID_SCS[$i]}"
    REPORT="${SINGLE_PATHS[$i]}"
    SCS_OUT="$OUT_DIR/$SCS_ID"
    mkdir -p "$SCS_OUT"

    echo "── $SCS_ID — single-file pass ($TOTAL files) ──────────────────────"

    done_count=0
    pids=()

    for file in "${ALL_FILES[@]}"; do
        [ "$done_count" -ge "$TOTAL" ] && break

        # simple semaphore: wait until a worker slot is free
        while [ "${#pids[@]}" -ge "$JOBS" ]; do
            live=()
            for pid in "${pids[@]}"; do
                kill -0 "$pid" 2>/dev/null && live+=("$pid")
            done
            pids=("${live[@]+"${live[@]}"}")
            [ "${#pids[@]}" -ge "$JOBS" ] && sleep 0.05
        done

        done_count=$((done_count + 1))
        local_done=$done_count   # capture for subshell

        # run in background; redirect verbose output to per-file log
        (
            rel="${file#${TARGET_DIR}/}"
            safe="${rel//\//__}"
            file_out="${SCS_OUT}/${safe}"
            mkdir -p "$file_out"

            bash "$REPORT" "$file" "$file_out" > "$file_out/stdout.log" 2>&1 || true

            # clean up srcML sidecars written into the source tree
            rm -f "${file}.xml" "${file}.json"

            # count findings in this file's output
            n=$(find "$file_out" -name "*_findings_*.json" \
                    -exec cat {} \; 2>/dev/null \
                | grep -c '"detector"' 2>/dev/null || true)

            printf "  [%5d/%d]  %-5s findings  %s\n" \
                "$local_done" "$TOTAL" "$n" "$rel"
        ) &
        pids+=($!)
    done

    # wait for all workers in this SCS pass
    wait
    echo "  ✓ $TOTAL files scanned"
    echo
done

# ── multi-file pass ───────────────────────────────────────────────────────────
# For each SCS that has smell_report_multi.sh, group files by parent directory
# and run multi-file detection on each group to catch interprocedural flows.

for i in $(seq 0 $((${#VALID_SCS[@]} - 1))); do
    MULTI_SCRIPT="${MULTI_PATHS[$i]}"
    [ -z "$MULTI_SCRIPT" ] && continue

    SCS_ID="${VALID_SCS[$i]}"
    echo "── $SCS_ID — multi-file pass (grouped by subdirectory) ─────────────"

    # collect unique parent directories
    PDIRS=()
    prev=""
    for file in "${ALL_FILES[@]}"; do
        [ "$(basename "$(dirname "$file")")" = "$prev" ] && continue
        pdir=$(dirname "$file")
        PDIRS+=("$pdir")
        prev=$(basename "$pdir")
    done

    group_count=0

    for pdir in "${PDIRS[@]}"; do
        # gather all target-extension files in this directory
        group_files=()
        IFS=',' read -ra EXTS2 <<< "$EXTENSIONS"
        for ext in "${EXTS2[@]}"; do
            while IFS= read -r f; do
                group_files+=("$f")
            done < <(find "$pdir" -maxdepth 1 -name "*.${ext}" -type f | sort)
        done

        [ "${#group_files[@]}" -lt 2 ] && continue  # skip single-file dirs

        rel="${pdir#${TARGET_DIR}/}"
        safe="${rel//\//__}"
        group_out="$OUT_DIR/multi/$SCS_ID/$safe"
        mkdir -p "$group_out"

        bash "$MULTI_SCRIPT" "${group_files[@]}" \
            > "$group_out/stdout.log" 2>&1 || true

        # clean up combined srcML sidecars left in source directory
        rm -f "${pdir}/combined.xml" "${pdir}/combined.json"

        # move any findings files the script wrote to its default output location
        # into our group_out dir so aggregation finds them
        find "$pdir" -maxdepth 1 -name "combined_findings_*.json" 2>/dev/null \
            | while IFS= read -r fj; do mv "$fj" "$group_out/"; done

        group_count=$((group_count + 1))
        n=$(find "$group_out" -name "*_findings_*.json" -exec cat {} \; 2>/dev/null \
            | grep -c '"detector"' 2>/dev/null || true)
        echo "  group [$group_count] $rel  (${#group_files[@]} files)  $n findings"
    done

    echo "  ✓ $group_count directory groups scanned"
    echo
done

# ── aggregate all findings ────────────────────────────────────────────────────
echo "── Aggregating findings ──────────────────────────────────────────────"

python3 - "$OUT_DIR" "$TARGET_DIR" "$TOTAL" "$SINGLE_IDS" << 'PYEOF'
import json, os, glob, sys
from collections import defaultdict

out_dir     = sys.argv[1]
target_dir  = sys.argv[2]
total_files = int(sys.argv[3])
scs_ids     = sys.argv[4].split()

def parse_findings(path):
    content = open(path).read().strip()
    findings, depth, buf = [], 0, ""
    for ch in content:
        if ch == "{":  depth += 1
        if depth > 0:  buf += ch
        if ch == "}":
            depth -= 1
            if depth == 0 and buf.strip():
                try:    findings.append(json.loads(buf))
                except: pass
                buf = ""
    return findings

all_findings = []
for jf in glob.glob(os.path.join(out_dir, "**", "*_findings_*.json"), recursive=True):
    all_findings.extend(parse_findings(jf))

# write aggregated findings as a proper JSON array
agg_path = os.path.join(out_dir, "findings_all.json")
with open(agg_path, "w") as f:
    json.dump(all_findings, f, indent=2)

# statistics
n         = len(all_findings)
n_error   = sum(1 for f in all_findings if f.get("severity")       == "error")
n_warn    = sum(1 for f in all_findings if f.get("severity")       == "warning")
files_hit = len({f.get("file","") for f in all_findings})

by_rule     = defaultdict(int)
by_detector = defaultdict(int)
by_file     = defaultdict(int)
for f in all_findings:
    by_rule[f.get("rule","?")]         += 1
    by_detector[f.get("detector","?")] += 1
    by_file[f.get("file","?")]         += 1

top_files = sorted(by_file.items(), key=lambda x: -x[1])[:20]
pct = lambda a, b: (f"{a*100//b}%" if b else "0%")

lines = [
    "════════════════════════════════════════════════════════════",
    " SmellDetect — Scan Summary",
    f" Target       : {target_dir}",
    f" SCS detectors: {' '.join(scs_ids)}",
    "════════════════════════════════════════════════════════════",
    "",
    f" Files scanned       : {total_files}",
    f" Files with findings : {files_hit}  ({pct(files_hit, total_files)})",
    f" Files clean         : {total_files - files_hit}  ({pct(total_files - files_hit, total_files)})",
    "",
    f" Total findings      : {n}",
    f"   error/vulnerability: {n_error}  ({pct(n_error, n)})",
    f"   warning/smell      : {n_warn}  ({pct(n_warn, n)})",
    "",
    " ── By rule ─────────────────────────────────────────────────",
]
for rule, cnt in sorted(by_rule.items(), key=lambda x: -x[1]):
    lines.append(f"   {rule:<35} {cnt:>5}")
lines += ["", " ── By detector ─────────────────────────────────────────────"]
for det, cnt in sorted(by_detector.items(), key=lambda x: -x[1]):
    lines.append(f"   {det:<35} {cnt:>5}")
lines += ["", f" ── Top {len(top_files)} files by finding count ─────────────────────────"]
for fpath, cnt in top_files:
    rel = fpath.replace(target_dir.rstrip("/") + "/", "")
    lines.append(f"   {cnt:>4}  {rel}")
lines += [
    "",
    f" Findings JSON : {agg_path}",
    "════════════════════════════════════════════════════════════",
]

report = "\n".join(lines)
print(report)
with open(os.path.join(out_dir, "summary.txt"), "w") as f:
    f.write(report + "\n")
print(f"\n Summary written to: {os.path.join(out_dir, 'summary.txt')}")
PYEOF

echo
echo " Output directory: $OUT_DIR"
