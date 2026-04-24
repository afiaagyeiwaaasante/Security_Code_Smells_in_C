#!/usr/bin/env bash
# evaluation/compare_report.sh
# Reads smelldetect_results.json, cppcheck_results.json, and joern_results.json
# and prints a side-by-side comparison table separated by tier.
#
# Tier 3 (limitation) cases are excluded from TP/FP/FN/TN counts —
# they represent documented detector boundaries, not evaluation failures.
#
# Output: evaluation/comparison_report.txt
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUR_RESULTS="$SCRIPT_DIR/smelldetect_results.json"
CPP_RESULTS="$PROJECT_ROOT/cppcheck/results/cppcheck_results.json"
JOERN_RESULTS="$PROJECT_ROOT/joern/results/joern_results.json"
REPORT_FILE="$SCRIPT_DIR/comparison_report.txt"

for f in "$OUR_RESULTS" "$CPP_RESULTS" "$JOERN_RESULTS"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: $f not found — run the corresponding benchmark script first"
        exit 1
    fi
done

python3 << PYEOF | tee "$REPORT_FILE"
import json

def load_jsonl(path):
    results = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            r = json.loads(line)
            results[r["test"]] = r
    return results

our   = load_jsonl("$OUR_RESULTS")
cpp   = load_jsonl("$CPP_RESULTS")
joern = load_jsonl("$JOERN_RESULTS")

def fmt_time(val):
    try:    return f"{float(val):.3f}s"
    except: return "     -"

def fmt_mem(val):
    try:
        kb = int(val)
        return f"{kb/1024:.1f} MB" if kb >= 1024 else f"{kb} KB"
    except: return "     -"

def fmt_det(val):
    return " FOUND" if val else "MISSED"

COL  = 30
LINE = "-" * (38 + 3 + COL + 3 + COL + 3 + COL)
HDR  = f"{'Test Case':<38} | {'--- SmellDetect ---':^{COL}} | {'--- cppcheck ---':^{COL}} | {'--- Joern ---':^{COL}}"
SUB  = (f"{'':38} | {'Time':>8} {'Mem':>9} {'Result':>9} |"
        f" {'Time':>8} {'Mem':>9} {'Result':>9} |"
        f" {'Time':>8} {'Mem':>9} {'Result':>9}")

def print_header(title):
    print()
    print("=" * len(HDR))
    print(f"  {title}")
    print("=" * len(HDR))
    print(SUB)
    print(HDR)
    print(LINE)

def print_row(test):
    o = our.get(test, {})
    c = cpp.get(test, {})
    j = joern.get(test, {})
    row = (f"{test:<38} |"
           f" {fmt_time(o.get('wall_time_s')):>8} {fmt_mem(o.get('peak_rss_kb')):>9} {fmt_det(o.get('detected')):>9} |"
           f" {fmt_time(c.get('wall_time_s')):>8} {fmt_mem(c.get('peak_rss_kb')):>9} {fmt_det(c.get('detected')):>9} |"
           f" {fmt_time(j.get('wall_time_s')):>8} {fmt_mem(j.get('peak_rss_kb')):>9} {fmt_det(j.get('detected')):>9}")
    print(row)

tier1 = [t for t, r in our.items() if r.get("tier") == "tier1"]
tier2 = [t for t, r in our.items() if r.get("tier") == "tier2"]
tier3 = [t for t, r in our.items() if r.get("tier") == "tier3"]

print_header("SCS004 CWE-416  TIER 1 — Smell Pattern Variants")
for t in tier1:
    print_row(t)
print(LINE)

print_header("SCS004 CWE-416  TIER 2 — Context Variants")
for t in tier2:
    print_row(t)
print(LINE)

if tier3:
    print_header("SCS004 CWE-416  TIER 3 — Known Limitation Cases (expected: MISSED)")
    for t in tier3:
        print_row(t)
    print(LINE)

# TP/TN/FP/FN — Tier 1 + Tier 2 only
eval_tests = {t: r for t, r in our.items() if r.get("tier") in ("tier1", "tier2")}

def tptnfpfn(ref_results, all_results):
    tp = tn = fp = fn = 0
    for test, r in ref_results.items():
        det = all_results.get(test, {}).get("detected", False)
        exp = r.get("expected") == "bad"
        if exp  and det:           tp += 1
        elif not exp and not det:  tn += 1
        elif not exp and det:      fp += 1
        elif exp and not det:      fn += 1
    return tp, tn, fp, fn

def pct(num, den):
    return f"{100*num/den:.1f}%" if den > 0 else " N/A"

def f1(prec_str, rec_str):
    try:
        p = float(prec_str.strip('%')) / 100
        r = float(rec_str.strip('%'))  / 100
        if p + r == 0: return " N/A"
        return f"{2*p*r/(p+r)*100:.1f}%"
    except: return " N/A"

o_tp, o_tn, o_fp, o_fn = tptnfpfn(eval_tests, our)
c_tp, c_tn, c_fp, c_fn = tptnfpfn(eval_tests, cpp)
j_tp, j_tn, j_fp, j_fn = tptnfpfn(eval_tests, joern)

o_prec = pct(o_tp, o_tp + o_fp);  o_rec = pct(o_tp, o_tp + o_fn)
c_prec = pct(c_tp, c_tp + c_fp);  c_rec = pct(c_tp, c_tp + c_fn)
j_prec = pct(j_tp, j_tp + j_fp);  j_rec = pct(j_tp, j_tp + j_fn)

print()
print("=" * len(HDR))
print("  Metrics (Tier 1 + Tier 2 only; Tier 3 limitation cases excluded)")
print("=" * len(HDR))
print(f"  {'':34} {'SmellDetect':>14}   {'cppcheck':>14}   {'Joern':>14}")
print(f"  {'True Positives  (TP)':34} {o_tp:>14}   {c_tp:>14}   {j_tp:>14}")
print(f"  {'True Negatives  (TN)':34} {o_tn:>14}   {c_tn:>14}   {j_tn:>14}")
print(f"  {'False Positives (FP)':34} {o_fp:>14}   {c_fp:>14}   {j_fp:>14}")
print(f"  {'False Negatives (FN)':34} {o_fn:>14}   {c_fn:>14}   {j_fn:>14}")
print(f"  {'Precision  TP/(TP+FP)':34} {o_prec:>14}   {c_prec:>14}   {j_prec:>14}")
print(f"  {'Recall     TP/(TP+FN)':34} {o_rec:>14}   {c_rec:>14}   {j_rec:>14}")
print(f"  {'F1-score   2PR/(P+R)':34} {f1(o_prec,o_rec):>14}   {f1(c_prec,c_rec):>14}   {f1(j_prec,j_rec):>14}")
print()

def avg_time(d): return sum(float(r["wall_time_s"]) for r in d.values() if r.get("wall_time_s")) / max(len(d), 1)
def avg_mem(d):  return sum(int(r["peak_rss_kb"])   for r in d.values() if r.get("peak_rss_kb"))  / max(len(d), 1)

print(f"  Avg wall time  : SmellDetect {avg_time(our):.3f}s    cppcheck {avg_time(cpp):.3f}s    Joern {avg_time(joern):.3f}s")
print(f"  Avg memory     : SmellDetect {avg_mem(our)/1024:.1f} MB   cppcheck {avg_mem(cpp)/1024:.1f} MB   Joern {avg_mem(joern)/1024:.1f} MB")
print()
print("=" * len(HDR))
PYEOF

echo
echo "Report saved to: $REPORT_FILE"
