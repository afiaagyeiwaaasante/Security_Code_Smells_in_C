# Security Code Smells in C — Detection & Analysis

> Master's Thesis Research Repository
> Tools: srcML · srcSlice · srcAttributor · cppcheck · Joern · Juliet Test Suite

---

## Overview

This repository contains the full detection and evaluation pipeline for **10 security code smells in C/C++ source code**. Each smell is an independent study with its own detectors, test cases, and three-way tool comparison (SmellDetect vs cppcheck vs Joern), benchmarked against the **NIST Juliet Test Suite**.

Detection is structural: source files are converted to srcML XML, annotated with data-slice information via srcSlice and srcAttributor, then queried by shell/Python detector scripts.

---

## Repository Structure

```
Security-Code-Smells/
├── README.md                        ← this file (includes SCS-to-CWE-to-Juliet mapping)
├── shared/
│   ├── pipeline.sh                  ← shared 3-stage pipeline (srcml→srcslice→srcattributor)
│   └── lib/
│       └── write_finding.sh         ← shared JSON finding writer
├── tools/                           ← srcML, srcSlice, srcAttributor, Joern (local installs)
│
└── SCS00X_<SmellName>/              ← one folder per security code smell
    ├── README.md                    ← smell description and evaluation results
    ├── src/
    │   ├── smell_report.sh          ← orchestrator: runs pipeline + all detectors
    │   ├── report.sh                ← human-readable report formatter
    │   └── detectors/               ← one detector script per pattern
    ├── testsuites/
    │   └── CWEXXX/                  ← Juliet-derived C/C++ test cases (bad + good)
    ├── evaluation/
    │   ├── run_smelldetect.sh          ← benchmarks SmellDetect on all test cases
    │   ├── compare_report.sh        ← generates side-by-side comparison table
    │   └── comparison_report.txt    ← TP/TN/FP/FN/Precision/Recall results
    ├── cppcheck/
    │   └── scripts/run_cppcheck.sh
    ├── joern/
    │   └── scripts/run_joern.sh
    └── docs/
        ├── pipeline.md              ← detector strategy and XML patterns
        ├── known_issues.md          ← false positives/negatives and limitations
        └── variants.md              ← Juliet variant analysis and group breakdown
```

---

## Security Code Smells Catalogue

| ID | Smell Name | Category | CWE Mapping | Juliet CWE |
|----|---|---|---|---|
| SCS001 | Dangerous Function Use | Memory Safety | CWE-120, CWE-676, CWE-242 | CWE-242 |
| SCS002 | Buffer Size Mismatch | Memory Safety | CWE-131, CWE-680 | CWE-680 |
| SCS003 | Missing NULL Check | Memory Safety | CWE-476, CWE-690 | CWE-476, CWE-690 |
| SCS004 | Use-After-Free Risk | Memory Safety | CWE-416, CWE-672 | CWE-416, CWE-672 |
| SCS005 | Memory Leak Pattern | Memory Safety | CWE-401, CWE-772 | CWE-401 |
| SCS006 | Integer Overflow Risk | Integer Handling | CWE-190, CWE-191 | CWE-190, CWE-191 |
| SCS007 | Signed/Unsigned Confusion | Integer Handling | CWE-194, CWE-195 | CWE-194, CWE-195 |
| SCS008 | Missing Format Specifier | Input Validation | CWE-134, CWE-686 | CWE-134 |
| SCS009 | Command Injection Risk | Input Validation | CWE-78, CWE-88 | CWE-78 |
| SCS010 | Hardcoded Sensitive Data | API Misuse | CWE-259, CWE-798 | CWE-259 |

---

## Detection Pipeline

```
C/C++ Source File
        │
        ▼
[Stage 1]  srcml --position --hash
        │  → <source>.xml   (srcML annotated XML)
        ▼
[Stage 2]  srcslice -i <xml> -o <json>
        │  → <source>.json  (data-slice profiles)
        ▼
[Stage 3]  srcattributor -i <json> -o <xml>
        │  → <source>.xml   (slice-annotated XML)
        ▼
[Detectors]  bash SCS00X/src/detectors/detect_*.sh
        │  → <name>_findings_<timestamp>.json
        │  → <name>_report_<timestamp>.txt
        ▼
[Evaluation] bash evaluation/compare_report.sh
           → comparison_report.txt  (TP/TN/FP/FN/Precision/Recall)
```

Stages 1–3 are handled by `shared/pipeline.sh`. Each smell's detectors parse the annotated XML using Python regex over srcML element patterns.

---

## Quick Start

Run the detector on a single file:

```bash
bash SCS003_Missing_Null_Check/src/smell_report.sh \
    SCS003_Missing_Null_Check/testsuites/CWE476/binary_if/bad_binary_if_01.c
```

Run the full evaluation benchmark for a smell:

```bash
cd SCS003_Missing_Null_Check
bash evaluation/run_smelldetect.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

---

## Dependencies

| Tool | Purpose |
|---|---|
| `srcml` | Stage 1 — converts C/C++ to annotated XML |
| `srcslice` | Stage 2 — produces data-slice JSON |
| `srcattributor` | Stage 3 — merges slice info back into XML |
| `cppcheck` | Baseline comparison tool |
| `joern` | Baseline comparison tool (CPG-based) |
| `python3` | Detector scripts and report generation |

Local tool builds are in `tools/` (excluded from git). Juliet test cases are at `Security-Code-Smells-in-C/benchmark/juliet/` (excluded from git, 106K files).

---

## Reproducibility

Test cases are adapted from the **NIST Juliet Test Suite for C/C++**:
https://samate.nist.gov/SARD/test-suites/116

Each smell folder contains 10 test cases (5 bad/good pairs) covering baseline, control-flow, interprocedural, and C++ class variants. Evaluation results are committed to `evaluation/comparison_report.txt` in each folder.