# SCS005 — Memory Leak Pattern (CWE-401)

## Description

A **Memory Leak** occurs when dynamically allocated memory is not released
before the last reference to it is removed. This is classified as **CWE-401:
Missing Release of Memory before Removing Last Reference** and can lead to
resource exhaustion, denial of service, and degraded system performance over
time.

This detector uses a three-stage static analysis pipeline (srcml → srcslice →
srcattributor) followed by three structural detectors built with srcQL queries
and XPath post-filtering.

---

## Detectors

| # | Detector | Pattern | Severity |
|---|----------|---------|----------|
| 1 | `no_free_on_exit` | `malloc()` called but `free()` never called in the same function | warning |
| 2 | `overwrite_leak` | pointer overwritten with new `malloc()` without freeing the original | warning |
| 3 | `new_no_delete` | C++ `new` allocated but `delete` never called before scope exit | warning |

---

## Quick start

```bash
# Single file
bash src/smell_report.sh testsuites/CWE401/int/bad_malloc_no_free_01.c

# C++ file
bash src/smell_report.sh testsuites/CWE401/new_delete/bad_new_no_delete_01.cpp

# Run full test suite
cd testsuites/CWE401 && bash run_test.sh
```

Output is written to `results/<category>/` automatically.

---

## Example output

```
========================================
 CWE-401 Memory Leak Detector
 Source  : bad_malloc_no_free_01.c
 Report  : results/int/bad_malloc_no_free_01_report_<ts>.txt
 Findings: results/int/bad_malloc_no_free_01_findings_<ts>.json
========================================
...
{
  "detector": "no_free_on_exit",
  "severity": "warning",
  "rule": "memoryLeak",
  "file": "bad_malloc_no_free_01.c",
  "line": 9,
  "col": 16,
  "varname": "data",
  "note": {
    "line": 9,
    "col": 16,
    "message": "malloc() in bad_malloc_no_free() — no free() on any exit path"
  }
}

 Total findings : 1
 Errors         : 0
 Warnings       : 1

 Breakdown by detector:
   no_free_on_exit           1
```

---

## Folder structure

```
SCS005_Memory_Leak_Pattern/
│
├── README.md
│
├── src/
│   ├── smell_report.sh          ← single-file entry point
│   ├── pipeline.sh              ← stages 1–3 (srcml → srcslice → srcattributor)
│   ├── report.sh                ← cppcheck-style report formatter
│   ├── detectors/
│   │   ├── detect_no_free_on_exit.sh
│   │   ├── detect_overwrite_leak.sh
│   │   └── detect_new_no_delete.sh
│   └── lib/
│       └── write_finding.sh     ← shared JSON finding writer
│
├── testsuites/
│   └── CWE401/
│       ├── run_test.sh          ← test suite runner
│       ├── int/                 ← malloc/free int cases (.c)
│       ├── early_return/        ← early-return leak cases (.c)
│       ├── overwrite/           ← pointer-overwrite leak cases (.c)
│       └── new_delete/          ← C++ new/delete cases (.cpp)
│
├── results/                     ← generated reports and findings (by category)
│
├── cppcheck/
│   ├── scripts/run_cppcheck.sh  ← cppcheck benchmark
│   └── results/
│
├── joern/
│   ├── scripts/run_joern.sh     ← Joern benchmark
│   └── results/
│
├── evaluation/
│   ├── run_our_tool.sh          ← our tool benchmark
│   ├── compare_report.sh        ← generates comparison table
│   ├── our_tool_results.json
│   └── comparison_report.txt
│
└── docs/
    ├── pipeline.md              ← pipeline architecture and detector queries
    ├── variants.md              ← Juliet variant coverage and test status
    └── known_issues.md          ← false negatives and limitations
```

---

## Tool comparison

```bash
bash evaluation/run_our_tool.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

Latest results (`evaluation/comparison_report.txt`):

| Test Case | Our Tool | cppcheck | Joern |
|-----------|----------|----------|-------|
| bad_malloc_no_free_01 | YES | YES | YES |
| good_malloc_with_free_01 | NO | NO | NO |
| bad_early_return_01 | NO (FN) | YES | NO |
| good_early_return_01 | NO | NO | NO |
| bad_overwrite_01 | YES | YES | NO |
| good_overwrite_01 | NO | NO | NO |
| bad_new_no_delete_01 | YES | NO | NO |
| good_new_delete_01 | NO | NO | NO |

**Detections (bad cases only): Our Tool 3/4 — cppcheck 3/4 — Joern 1/4**

Our tool detects the C++ `new`-without-`delete` pattern (`bad_new_no_delete_01`)
that cppcheck misses with its standard `memleak` checker. cppcheck detects the
early-return leak (`bad_early_return_01`) that our intra-procedural post-filter
misses (known limitation: free() present on the normal path suppresses the
finding). Joern's generic name-set subtraction query only catches the simple
`malloc`-no-`free` case; overwrite and C++ patterns require more targeted queries.

---

## Requirements

- `srcml` — srcML toolkit
- `srcslice` — data-flow slice analysis
- `srcattributor` — merges slice data into srcML XML
- `xmllint` — XPath extraction from XML
- `cppcheck` — comparison benchmark only
- `joern` — comparison benchmark only
- `python3` — summary report generation

---

## Documentation

| Doc | Contents |
|---|---|
| `docs/pipeline.md` | Three-stage pipeline, all 3 detector queries explained |
| `docs/variants.md` | Juliet variant coverage by detector and flow type |
| `docs/known_issues.md` | Known false negatives and tool limitations |
