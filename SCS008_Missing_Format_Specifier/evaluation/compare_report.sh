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
    echo "NOTE: $JOERN_RESULTS not found — Joern column will show N/A"
    echo "      Run joern/scripts/run_joern.sh to populate Joern results."
    JOERN_RESULTS=""
fi

python3 << PYEOF | tee "$REPORT_FILE"
import json

def load_jsonl(path):
    results = {}
    if not path:
        return results
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                results[r["test"]] = r
    except FileNotFoundError:
        pass
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

def fmt_det(val, missing=False):
    if missing: return " N/A"
    return "FOUND" if val else "MISSED"

COL = 27
header_tool = f"{'Test Case':<36} | {'--- SmellDetect ---':^{COL}} | {'--- cppcheck ---':^{COL}} | {'--- Joern ---':^{COL}}"
header_sub  = f"{'':36} | {'Time':>7} {'Mem Used':>9} {'Detect':>7} | {'Time':>7} {'Mem Used':>9} {'Detect':>7} | {'Time':>7} {'Mem Used':>9} {'Detect':>7}"
LINE = "-" * len(header_tool)

print()
print("=" * len(header_tool))
print("  SCS008 CWE-134  Tool Comparison: SmellDetect vs cppcheck vs Joern")
print("=" * len(header_tool))
print(header_sub)
print(header_tool)
print(LINE)

for test in all_tests:
    o = our.get(test, {})
    c = cpp.get(test, {})
    j = joern.get(test, {})
    joern_missing = not joern
    print(
        f"{test:<36} | "
        f"{fmt_time(o.get('wall_time_s')):>7} {fmt_mem(o.get('peak_rss_kb')):>9} {fmt_det(o.get('detected')):>7} | "
        f"{fmt_time(c.get('wall_time_s')):>7} {fmt_mem(c.get('peak_rss_kb')):>9} {fmt_det(c.get('detected')):>7} | "
        f"{fmt_time(j.get('wall_time_s') if j else None):>7} {fmt_mem(j.get('peak_rss_kb') if j else None):>9} {fmt_det(j.get('detected') if j else None, missing=joern_missing):>7}"
    )

print(LINE)
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
joern_tp, joern_tn, joern_fp, joern_fn = tptnfpfn(joern) if joern else (None, None, None, None)

our_det   = sum(1 for r in our.values()   if r.get("detected"))
cpp_det   = sum(1 for r in cpp.values()   if r.get("detected"))
joern_det = sum(1 for r in joern.values() if r.get("detected")) if joern else None
total     = len(all_tests)

our_times   = [float(r["wall_time_s"]) for r in our.values()   if r.get("wall_time_s")]
cpp_times   = [float(r["wall_time_s"]) for r in cpp.values()   if r.get("wall_time_s")]
joern_times = [float(r["wall_time_s"]) for r in joern.values() if r.get("wall_time_s")] if joern else []
our_mems    = [int(r["peak_rss_kb"])   for r in our.values()   if r.get("peak_rss_kb")]
cpp_mems    = [int(r["peak_rss_kb"])   for r in cpp.values()   if r.get("peak_rss_kb")]
joern_mems  = [int(r["peak_rss_kb"])   for r in joern.values() if r.get("peak_rss_kb")] if joern else []

joern_det_str = f"{joern_det}/{total}" if joern_det is not None else "N/A"
print(f"  Detected       : SmellDetect detected {our_det}/{total}   cppcheck {cpp_det}/{total}   Joern {joern_det_str}")
if our_times and cpp_times:
    joern_time_str = f"{sum(joern_times)/len(joern_times):.3f}s" if joern_times else "N/A"
    print(f"  Avg Run Time : SmellDetect {sum(our_times)/len(our_times):.3f}s   cppcheck {sum(cpp_times)/len(cpp_times):.3f}s   Joern {joern_time_str}")
if our_mems and cpp_mems:
    joern_mem_str = f"{sum(joern_mems)/len(joern_mems)/1024:.1f} MB" if joern_mems else "N/A"
    print(f"  Avg Memory Used  : SmellDetect {sum(our_mems)/len(our_mems)/1024:.1f} MB   cppcheck {sum(cpp_mems)/len(cpp_mems)/1024:.1f} MB   Joern {joern_mem_str}")
print()

def fmt_metric(val):
    return f"{val:>12}" if val is not None else f"{'N/A':>12}"

def fmt_pct(num, den):
    return f"{pct(num, den):>12}" if num is not None else f"{'N/A':>12}"

print(f"  {'':30} {'SmellDetect':>12}   {'cppcheck':>12}   {'Joern':>12}")
print(f"  {'True Positives  (TP)':30} {fmt_metric(our_tp)}   {fmt_metric(cpp_tp)}   {fmt_metric(joern_tp)}")
print(f"  {'True Negatives  (TN)':30} {fmt_metric(our_tn)}   {fmt_metric(cpp_tn)}   {fmt_metric(joern_tn)}")
print(f"  {'False Positives (FP)':30} {fmt_metric(our_fp)}   {fmt_metric(cpp_fp)}   {fmt_metric(joern_fp)}")
print(f"  {'False Negatives (FN)':30} {fmt_metric(our_fn)}   {fmt_metric(cpp_fn)}   {fmt_metric(joern_fn)}")
print(f"  {'Precision  TP/(TP+FP)':30} {fmt_pct(our_tp, our_tp+our_fp) if our_tp is not None else fmt_metric(None)}   {fmt_pct(cpp_tp, cpp_tp+cpp_fp) if cpp_tp is not None else fmt_metric(None)}   {fmt_pct(joern_tp, joern_tp+joern_fp) if joern_tp is not None else fmt_metric(None)}")
print(f"  {'Recall     TP/(TP+FN)':30} {fmt_pct(our_tp, our_tp+our_fn) if our_tp is not None else fmt_metric(None)}   {fmt_pct(cpp_tp, cpp_tp+cpp_fn) if cpp_tp is not None else fmt_metric(None)}   {fmt_pct(joern_tp, joern_tp+joern_fn) if joern_tp is not None else fmt_metric(None)}")
print()
print("=" * len(header_tool))
PYEOF

echo
echo "Report saved to: $REPORT_FILE"
