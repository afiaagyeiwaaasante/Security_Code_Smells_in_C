#!/usr/bin/env bash
# evaluation/compare_report.sh
# Reads smelldetect_results.json, cppcheck_results.json, and joern_results.json
# and prints a side-by-side comparison table (time, memory used, detection).
# Output: evaluation/comparison_report.txt
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUR_RESULTS="$SCRIPT_DIR/smelldetect_results.json"
CPP_RESULTS="$PROJECT_ROOT/cppcheck/results/cppcheck_results.json"
JOERN_RESULTS="$PROJECT_ROOT/joern/results/joern_results.json"
REPORT_FILE="$SCRIPT_DIR/comparison_report.txt"

if [ ! -f "$OUR_RESULTS" ]; then
    echo "ERROR: $OUR_RESULTS not found — run evaluation/run_smelldetect.sh first"
    exit 1
fi
if [ ! -f "$CPP_RESULTS" ]; then
    echo "ERROR: $CPP_RESULTS not found — run cppcheck/scripts/run_cppcheck.sh first"
    exit 1
fi
if [ ! -f "$JOERN_RESULTS" ]; then
    echo "ERROR: $JOERN_RESULTS not found — run joern/scripts/run_joern.sh first"
    exit 1
fi

python3 << PYEOF | tee "$REPORT_FILE"
import json

def load_jsonl(path):
    results = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            results[r["test"]] = r
    return results

our   = load_jsonl("$OUR_RESULTS")
cpp   = load_jsonl("$CPP_RESULTS")
joern = load_jsonl("$JOERN_RESULTS")

all_tests = list(our.keys())

def fmt_time(val):
    try:    return f"{float(val):.3f}s"
    except: return "   -   "

def fmt_mem(val):
    try:
        kb = int(val)
        return f"{kb/1024:.1f} MB" if kb >= 1024 else f"{kb} KB"
    except:
        return "   -   "

def fmt_det(val):
    return "FOUND" if val else "MISSED"

COL = 27
header_tool = f"{'Test Case':<36} | {'--- SmellDetect ---':^{COL}} | {'--- cppcheck ---':^{COL}} | {'--- Joern ---':^{COL}}"
header_sub  = f"{'':36} | {'Time':>7} {'Mem Used':>9} {'Detect':>7} | {'Time':>7} {'Mem Used':>9} {'Detect':>7} | {'Time':>7} {'Mem Used':>9} {'Detect':>7}"
LINE = "-" * len(header_tool)

print()
print("=" * len(header_tool))
print("  SCS004 CWE-416  Tool Comparison: SmellDetect vs cppcheck vs Joern")
print("=" * len(header_tool))
print(header_sub)
print(header_tool)
print(LINE)

for test in all_tests:
    o = our.get(test, {})
    c = cpp.get(test, {})
    j = joern.get(test, {})
    print(f"{test:<36} | {fmt_time(o.get('wall_time_s')):>7} {fmt_mem(o.get('peak_rss_kb')):>9} {fmt_det(o.get('detected')):>7} | {fmt_time(c.get('wall_time_s')):>7} {fmt_mem(c.get('peak_rss_kb')):>9} {fmt_det(c.get('detected')):>7} | {fmt_time(j.get('wall_time_s')):>7} {fmt_mem(j.get('peak_rss_kb')):>9} {fmt_det(j.get('detected')):>7}")

print(LINE)
print()

our_det   = sum(1 for r in our.values()   if r.get("detected"))
cpp_det   = sum(1 for r in cpp.values()   if r.get("detected"))
joern_det = sum(1 for r in joern.values() if r.get("detected"))
total     = len(all_tests)

our_times   = [float(r["wall_time_s"]) for r in our.values()   if r.get("wall_time_s")]
cpp_times   = [float(r["wall_time_s"]) for r in cpp.values()   if r.get("wall_time_s")]
joern_times = [float(r["wall_time_s"]) for r in joern.values() if r.get("wall_time_s")]
our_mems    = [int(r["peak_rss_kb"])   for r in our.values()   if r.get("peak_rss_kb")]
cpp_mems    = [int(r["peak_rss_kb"])   for r in cpp.values()   if r.get("peak_rss_kb")]
joern_mems  = [int(r["peak_rss_kb"])   for r in joern.values() if r.get("peak_rss_kb")]

print(f"  Detected       : SmellDetect detected {our_det}/{total}   cppcheck {cpp_det}/{total}   Joern {joern_det}/{total}")
if our_times and cpp_times and joern_times:
    print(f"  Avg Run Time : SmellDetect {sum(our_times)/len(our_times):.3f}s   cppcheck {sum(cpp_times)/len(cpp_times):.3f}s   Joern {sum(joern_times)/len(joern_times):.3f}s")
if our_mems and cpp_mems and joern_mems:
    print(f"  Avg Memory Used  : SmellDetect {sum(our_mems)/len(our_mems)/1024:.1f} MB   cppcheck {sum(cpp_mems)/len(cpp_mems)/1024:.1f} MB   Joern {sum(joern_mems)/len(joern_mems)/1024:.1f} MB")
print()

def expected(test_name):
    return test_name.startswith("bad_")

def tptnfpfn(results):
    tp = tn = fp = fn = 0
    for test, r in results.items():
        det = r.get("detected", False)
        exp = expected(test)
        if exp and det:           tp += 1
        elif not exp and not det: tn += 1
        elif not exp and det:     fp += 1
        elif exp and not det:     fn += 1
    return tp, tn, fp, fn

def pct(num, den):
    return f"{100*num/den:.1f}%" if den > 0 else " N/A"

our_tp,   our_tn,   our_fp,   our_fn   = tptnfpfn(our)
cpp_tp,   cpp_tn,   cpp_fp,   cpp_fn   = tptnfpfn(cpp)
joern_tp, joern_tn, joern_fp, joern_fn = tptnfpfn(joern)

print(f"  {'':30} {'SmellDetect':>12}   {'cppcheck':>12}   {'Joern':>12}")
print(f"  {'True Positives  (TP)':30} {our_tp:>12}   {cpp_tp:>12}   {joern_tp:>12}")
print(f"  {'True Negatives  (TN)':30} {our_tn:>12}   {cpp_tn:>12}   {joern_tn:>12}")
print(f"  {'False Positives (FP)':30} {our_fp:>12}   {cpp_fp:>12}   {joern_fp:>12}")
print(f"  {'False Negatives (FN)':30} {our_fn:>12}   {cpp_fn:>12}   {joern_fn:>12}")
print(f"  {'Precision  TP/(TP+FP)':30} {pct(our_tp, our_tp+our_fp):>12}   {pct(cpp_tp, cpp_tp+cpp_fp):>12}   {pct(joern_tp, joern_tp+joern_fp):>12}")
print(f"  {'Recall     TP/(TP+FN)':30} {pct(our_tp, our_tp+our_fn):>12}   {pct(cpp_tp, cpp_tp+cpp_fn):>12}   {pct(joern_tp, joern_tp+joern_fn):>12}")
print()
print("=" * len(header_tool))
PYEOF

echo
echo "Report saved to: $REPORT_FILE"
