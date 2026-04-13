#!/usr/bin/env python3
"""
generate_figures.py
Reads evaluation JSON files for SCS001-SCS010 and produces one figure per analysis.
Output: docs/figures/fig1_recall_precision.png  ... fig6_complexity.png
"""

import json
import os
import glob
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

# ── paths ──────────────────────────────────────────────────────────────────
ROOT   = os.path.dirname(os.path.abspath(__file__)) + "/.."
OUTDIR = os.path.join(ROOT, "docs/figures")
os.makedirs(OUTDIR, exist_ok=True)

SCS_ORDER = [f"SCS{i:03d}" for i in range(1, 11)]

SCS_META = {
    "SCS001": dict(smell="Dangerous Function Use",    cwe=242, detectors=1, mechanism="srcQL"),
    "SCS002": dict(smell="Buffer Size Mismatch",      cwe=680, detectors=2, mechanism="srcQL"),
    "SCS003": dict(smell="Missing NULL Check",        cwe=476, detectors=6, mechanism="srcQL"),
    "SCS004": dict(smell="Use-After-Free Risk",       cwe=416, detectors=7, mechanism="srcQL + FOLLOWED BY"),
    "SCS005": dict(smell="Memory Leak Pattern",       cwe=401, detectors=3, mechanism="srcQL + XPath"),
    "SCS006": dict(smell="Integer Overflow Risk",     cwe=190, detectors=3, mechanism="srcQL + XPath guard"),
    "SCS007": dict(smell="Signed/Unsigned Confusion", cwe=195, detectors=3, mechanism="srcQL + XPath guard"),
    "SCS008": dict(smell="Missing Format Specifier",  cwe=134, detectors=3, mechanism="srcQL + XPath + taint"),
    "SCS009": dict(smell="Command Injection Risk",    cwe=78,  detectors=3, mechanism="srcQL + XPath + taint"),
    "SCS010": dict(smell="Hardcoded Sensitive Data",  cwe=259, detectors=3, mechanism="pure XPath"),
}

SHORT = {
    "SCS001": "Dangerous\nFunction",
    "SCS002": "Buffer Size\nMismatch",
    "SCS003": "Missing\nNULL Check",
    "SCS004": "Use-After\n-Free",
    "SCS005": "Memory\nLeak",
    "SCS006": "Integer\nOverflow",
    "SCS007": "Signed/Unsigned\nConfusion",
    "SCS008": "Missing Format\nSpecifier",
    "SCS009": "Command\nInjection",
    "SCS010": "Hardcoded\nSensitive Data",
}

# ── data loading ────────────────────────────────────────────────────────────
def load_jsonl(path):
    results = {}
    if not path or not os.path.exists(path):
        return results
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                r = json.loads(line)
                results[r["test"]] = r
    return results

def find_file(scs_prefix, rel):
    dirs = glob.glob(os.path.join(ROOT, f"{scs_prefix}*"))
    for d in dirs:
        p = os.path.join(d, rel)
        if os.path.exists(p):
            return p
    return None

def load_all():
    data = {}
    for scs in SCS_ORDER:
        sd    = load_jsonl(find_file(scs, "evaluation/smelldetect_results.json"))
        cpp   = load_jsonl(find_file(scs, "cppcheck/results/cppcheck_results.json"))
        joern = load_jsonl(find_file(scs, "joern/results/joern_results.json"))
        data[scs] = dict(sd=sd, cpp=cpp, joern=joern)
    return data

def metrics(results):
    tp = tn = fp = fn = 0
    for test, r in results.items():
        det = r.get("detected", False)
        exp = test.startswith("bad_")
        if exp and det:           tp += 1
        elif not exp and not det: tn += 1
        elif not exp and det:     fp += 1
        elif exp and not det:     fn += 1
    recall    = tp / (tp + fn) * 100 if (tp + fn) > 0 else None
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else None
    return dict(tp=tp, tn=tn, fp=fp, fn=fn, recall=recall, precision=precision)

# palette
C_SD    = "#2563EB"   # blue
C_CPP   = "#16A34A"   # green
C_JOERN = "#DC2626"   # red

# ════════════════════════════════════════════════════════════════════════════
# Figure 1 — Recall & Precision by tool and smell
# ════════════════════════════════════════════════════════════════════════════
def fig1(data):
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle("Analysis 1: Recall & Precision by Tool and Smell", fontsize=14, fontweight="bold")

    x = np.arange(len(SCS_ORDER))
    w = 0.25

    for ax_idx, (metric_key, title) in enumerate([("recall", "Recall (%)"), ("precision", "Precision (%)")]):
        ax = axes[ax_idx]
        sd_vals, cpp_vals, joern_vals = [], [], []
        for scs in SCS_ORDER:
            m_sd    = metrics(data[scs]["sd"])
            m_cpp   = metrics(data[scs]["cpp"])
            m_joern = metrics(data[scs]["joern"])
            sd_vals.append(m_sd[metric_key] if m_sd[metric_key] is not None else 0)
            cpp_vals.append(m_cpp[metric_key] if m_cpp[metric_key] is not None else 0)
            joern_vals.append(m_joern[metric_key] if m_joern[metric_key] is not None else 0)

        b1 = ax.bar(x - w, sd_vals,    w, label="SmellDetect", color=C_SD,    alpha=0.85)
        b2 = ax.bar(x,     cpp_vals,   w, label="cppcheck",    color=C_CPP,   alpha=0.85)
        b3 = ax.bar(x + w, joern_vals, w, label="Joern",       color=C_JOERN, alpha=0.85)

        ax.set_ylim(0, 115)
        ax.set_ylabel(title, fontsize=11)
        ax.set_xticks(x)
        ax.set_xticklabels([SHORT[s] for s in SCS_ORDER], fontsize=7.5)
        ax.axhline(100, color="gray", linewidth=0.6, linestyle="--")
        ax.legend(fontsize=9)
        ax.set_title(title, fontsize=12)
        ax.grid(axis="y", alpha=0.3)

        for bars in [b1, b2, b3]:
            for bar in bars:
                h = bar.get_height()
                if h > 0:
                    ax.text(bar.get_x() + bar.get_width()/2, h + 1,
                            f"{h:.0f}", ha="center", va="bottom", fontsize=6)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR, "fig1_recall_precision.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("✓ fig1_recall_precision.png")

# ════════════════════════════════════════════════════════════════════════════
# Figure 2 — Performance trade-off (wall time + RSS)
# ════════════════════════════════════════════════════════════════════════════
def fig2(data):
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle("Analysis 2: Performance Trade-off (Wall Time & Memory)", fontsize=14, fontweight="bold")

    x = np.arange(len(SCS_ORDER))
    w = 0.25

    for ax_idx, (field, divisor, ylabel, title) in enumerate([
        ("wall_time_s", 1,    "Avg Wall Time (s)",  "Wall Time per Test Case"),
        ("peak_rss_kb", 1024, "Avg Peak RSS (MB)",  "Peak Memory per Test Case"),
    ]):
        ax = axes[ax_idx]
        sd_v, cpp_v, joern_v = [], [], []
        for scs in SCS_ORDER:
            def avg(results):
                vals = [r[field] for r in results.values() if field in r]
                return (sum(vals) / len(vals) / divisor) if vals else 0
            sd_v.append(avg(data[scs]["sd"]))
            cpp_v.append(avg(data[scs]["cpp"]))
            joern_v.append(avg(data[scs]["joern"]))

        ax.bar(x - w, sd_v,    w, label="SmellDetect", color=C_SD,    alpha=0.85)
        ax.bar(x,     cpp_v,   w, label="cppcheck",    color=C_CPP,   alpha=0.85)
        ax.bar(x + w, joern_v, w, label="Joern",       color=C_JOERN, alpha=0.85)

        ax.set_ylabel(ylabel, fontsize=11)
        ax.set_xticks(x)
        ax.set_xticklabels([SHORT[s] for s in SCS_ORDER], fontsize=7.5)
        ax.legend(fontsize=9)
        ax.set_title(title, fontsize=12)
        ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR, "fig2_performance.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("✓ fig2_performance.png")

# ════════════════════════════════════════════════════════════════════════════
# Figure 3 — Smell detection difficulty (ranked)
# ════════════════════════════════════════════════════════════════════════════
def fig3(data):
    rows = []
    for scs in SCS_ORDER:
        m_sd    = metrics(data[scs]["sd"])
        m_cpp   = metrics(data[scs]["cpp"])
        m_joern = metrics(data[scs]["joern"])
        recalls = [v for v in [m_sd["recall"], m_cpp["recall"], m_joern["recall"]] if v is not None]
        best = max(recalls) if recalls else 0
        agg  = sum(recalls) / len(recalls) if recalls else 0
        rows.append((scs, SCS_META[scs]["smell"], best, agg))

    rows.sort(key=lambda r: (-r[2], -r[3]))

    labels   = [f"{r[0]}\n{r[1]}" for r in rows]
    best_r   = [r[2] for r in rows]
    agg_r    = [r[3] for r in rows]

    def color(v):
        if v >= 90: return "#16A34A"
        if v >= 60: return "#F59E0B"
        return "#DC2626"

    fig, ax = plt.subplots(figsize=(12, 7))
    fig.suptitle("Analysis 3: Smell Detection Difficulty (Ranked by Best-Tool Recall)", fontsize=13, fontweight="bold")

    y = np.arange(len(rows))
    h = 0.35
    colors = [color(v) for v in best_r]
    ax.barh(y + h/2, best_r, h, label="Best-tool recall",   color=colors, alpha=0.85)
    ax.barh(y - h/2, agg_r,  h, label="Aggregate recall",   color="steelblue", alpha=0.55)

    ax.set_xlim(0, 115)
    ax.set_xlabel("Recall (%)", fontsize=11)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8.5)
    ax.axvline(90, color="#16A34A", linewidth=1, linestyle="--", alpha=0.6, label="Easy threshold (90%)")
    ax.axvline(60, color="#F59E0B", linewidth=1, linestyle="--", alpha=0.6, label="Moderate threshold (60%)")
    ax.legend(fontsize=9, loc="lower right")
    ax.grid(axis="x", alpha=0.3)

    for i, (b, a) in enumerate(zip(best_r, agg_r)):
        ax.text(b + 1, i + h/2, f"{b:.0f}%", va="center", fontsize=8)
        ax.text(a + 1, i - h/2, f"{a:.0f}%", va="center", fontsize=8, color="steelblue")

    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR, "fig3_difficulty.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("✓ fig3_difficulty.png")

# ════════════════════════════════════════════════════════════════════════════
# Figure 4 — Tool complementarity (stacked bar of bad-case detection groups)
# ════════════════════════════════════════════════════════════════════════════
def fig4(data):
    group_labels = [
        "All three",
        "SD + Joern",
        "SD + cppcheck",
        "SD only",
        "Joern only",
        "cppcheck only",
        "None",
    ]
    group_colors = ["#1D4ED8", "#60A5FA", "#34D399", "#93C5FD", "#F87171", "#86EFAC", "#D1D5DB"]

    matrix = {g: [] for g in group_labels}

    for scs in SCS_ORDER:
        sd_r    = data[scs]["sd"]
        cpp_r   = data[scs]["cpp"]
        joern_r = data[scs]["joern"]
        counts  = {g: 0 for g in group_labels}
        bad_tests = [t for t in sd_r if t.startswith("bad_")]
        for t in bad_tests:
            sd_d    = sd_r.get(t, {}).get("detected", False)
            cpp_d   = cpp_r.get(t, {}).get("detected", False)
            joern_d = joern_r.get(t, {}).get("detected", False)
            if sd_d and cpp_d and joern_d:    counts["All three"] += 1
            elif sd_d and joern_d:            counts["SD + Joern"] += 1
            elif sd_d and cpp_d:              counts["SD + cppcheck"] += 1
            elif sd_d:                        counts["SD only"] += 1
            elif joern_d:                     counts["Joern only"] += 1
            elif cpp_d:                       counts["cppcheck only"] += 1
            else:                             counts["None"] += 1
        for g in group_labels:
            matrix[g].append(counts[g])

    fig, ax = plt.subplots(figsize=(14, 6))
    fig.suptitle("Analysis 4: Tool Complementarity — Bad Case Detection Groups", fontsize=13, fontweight="bold")

    x     = np.arange(len(SCS_ORDER))
    bottoms = np.zeros(len(SCS_ORDER))

    for g, col in zip(group_labels, group_colors):
        vals = np.array(matrix[g])
        ax.bar(x, vals, bottom=bottoms, label=g, color=col, alpha=0.9)
        for i, (v, b) in enumerate(zip(vals, bottoms)):
            if v > 0:
                ax.text(x[i], b + v/2, str(v), ha="center", va="center", fontsize=8, fontweight="bold")
        bottoms += vals

    ax.set_xticks(x)
    ax.set_xticklabels([SHORT[s] for s in SCS_ORDER], fontsize=8)
    ax.set_ylabel("Number of bad test cases", fontsize=11)
    ax.legend(fontsize=8, bbox_to_anchor=(1.01, 1), loc="upper left")
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR, "fig4_complementarity.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("✓ fig4_complementarity.png")

# ════════════════════════════════════════════════════════════════════════════
# Figure 5 — FN root cause taxonomy
# ════════════════════════════════════════════════════════════════════════════
def fig5():
    # Source: analysis_report.md root cause summary table
    causes = [
        "Flow reasoning\nrequired",
        "Early-return /\nconditional path",
        "Interprocedural /\ncross-file taint",
        "Preprocessor\nloss",
        "Name-based\ntracking limitation",
    ]
    totals   = [42, 5, 2, 2, 2]
    sd_fns   = [0,  1, 2, 0, 0]
    cpp_fns  = [39, 1, 0, 0, 1]
    joern_fns= [3,  3, 0, 2, 1]

    x = np.arange(len(causes))
    w = 0.25

    fig, ax = plt.subplots(figsize=(13, 6))
    fig.suptitle("Analysis 5: False Negative Root Cause Taxonomy", fontsize=13, fontweight="bold")

    ax.bar(x - w, sd_fns,    w, label="SmellDetect", color=C_SD,    alpha=0.85)
    ax.bar(x,     cpp_fns,   w, label="cppcheck",    color=C_CPP,   alpha=0.85)
    ax.bar(x + w, joern_fns, w, label="Joern",       color=C_JOERN, alpha=0.85)

    # total annotation
    for i, t in enumerate(totals):
        ax.text(x[i], max(sd_fns[i], cpp_fns[i], joern_fns[i]) + 1.2,
                f"total={t}", ha="center", fontsize=8, color="gray")

    ax.set_xticks(x)
    ax.set_xticklabels(causes, fontsize=9)
    ax.set_ylabel("Number of False Negatives", fontsize=11)
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR, "fig5_fn_taxonomy.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("✓ fig5_fn_taxonomy.png")

# ════════════════════════════════════════════════════════════════════════════
# Figure 6 — Query complexity vs SmellDetect recall
# ════════════════════════════════════════════════════════════════════════════
def fig6(data):
    detector_counts = [SCS_META[s]["detectors"] for s in SCS_ORDER]
    sd_recalls = []
    for scs in SCS_ORDER:
        m = metrics(data[scs]["sd"])
        sd_recalls.append(m["recall"] if m["recall"] is not None else 0)

    mechanisms = [SCS_META[s]["mechanism"] for s in SCS_ORDER]
    mech_colors = {
        "srcQL":                  "#2563EB",
        "srcQL + FOLLOWED BY":    "#7C3AED",
        "srcQL + XPath":          "#0891B2",
        "srcQL + XPath guard":    "#0D9488",
        "srcQL + XPath + taint":  "#D97706",
        "pure XPath":             "#DC2626",
    }

    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle("Analysis 6: Query Complexity vs SmellDetect Detection Effectiveness", fontsize=13, fontweight="bold")

    # Left: scatter detector count vs recall
    ax = axes[0]
    for i, scs in enumerate(SCS_ORDER):
        col = mech_colors.get(mechanisms[i], "gray")
        ax.scatter(detector_counts[i], sd_recalls[i], color=col, s=120, zorder=3)
        ax.annotate(scs, (detector_counts[i], sd_recalls[i]),
                    textcoords="offset points", xytext=(6, 3), fontsize=7.5)

    # regression line
    r = np.corrcoef(detector_counts, sd_recalls)[0, 1]
    m_fit, b_fit = np.polyfit(detector_counts, sd_recalls, 1)
    xs = np.linspace(min(detector_counts)-0.3, max(detector_counts)+0.3, 100)
    ax.plot(xs, m_fit*xs + b_fit, "k--", linewidth=1, alpha=0.5, label=f"r = {r:.2f}")

    ax.set_xlabel("Number of Detectors", fontsize=11)
    ax.set_ylabel("SmellDetect Recall (%)", fontsize=11)
    ax.set_title("Detector Count vs Recall", fontsize=11)
    ax.set_ylim(40, 110)
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)

    # Right: bar chart coloured by mechanism
    ax2 = axes[1]
    colors_bar = [mech_colors.get(m, "gray") for m in mechanisms]
    bars = ax2.bar(np.arange(len(SCS_ORDER)), sd_recalls, color=colors_bar, alpha=0.85)
    ax2.set_xticks(np.arange(len(SCS_ORDER)))
    ax2.set_xticklabels([s.replace("SCS0", "S") for s in SCS_ORDER], fontsize=9)
    ax2.set_ylabel("SmellDetect Recall (%)", fontsize=11)
    ax2.set_title("Recall by Smell (coloured by mechanism)", fontsize=11)
    ax2.set_ylim(0, 115)
    ax2.axhline(100, color="gray", linewidth=0.6, linestyle="--")
    ax2.grid(axis="y", alpha=0.3)
    for bar, v in zip(bars, sd_recalls):
        ax2.text(bar.get_x() + bar.get_width()/2, v + 1.5, f"{v:.0f}%",
                 ha="center", va="bottom", fontsize=8)

    # legend for mechanisms
    patches = [mpatches.Patch(color=c, label=m) for m, c in mech_colors.items()]
    ax2.legend(handles=patches, fontsize=7, loc="lower right")

    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR, "fig6_complexity.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("✓ fig6_complexity.png")

# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("Loading data...")
    data = load_all()
    print("Generating figures...\n")
    fig1(data)
    fig2(data)
    fig3(data)
    fig4(data)
    fig5()
    fig6(data)
    print(f"\nAll figures saved to: {OUTDIR}")
