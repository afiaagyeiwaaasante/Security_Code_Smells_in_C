# SCS004 — Use After Free (CWE-416)

## Description

A **Use After Free** occurs when a program continues to use a pointer after
the memory it points to has been freed. This is classified as **CWE-416: Use
After Free** and can lead to program crashes, data corruption, or exploitable
memory corruption vulnerabilities.

This detector uses a three-stage static analysis pipeline (srcml → srcslice →
srcattributor) followed by structural detectors built with srcQL and xmllint.

---

## Detectors

| # | Detector | Pattern | Severity |
|---|---|---|---|
| 1 | `use_after_free` | `free(ptr)` then `ptr->field`, `*ptr`, or `ptr[idx]` in same function | error |
| 2 | `double_free` | `free(ptr)` called twice on same pointer without reassignment | error |
| 3 | `interprocedural_uaf` | pointer freed in callee; caller uses pointer after the call | error / warning |

---

## Quick start

```bash
# Single file
bash src/smell_report.sh testsuites/CWE416/char/bad_use_after_free_01.c

# Multi-file (cross-file interprocedural)
bash src/smell_report_multi.sh \
    testsuites/CWE416/interprocedural/bad_uaf_22a.c \
    testsuites/CWE416/interprocedural/bad_uaf_22b.c

# Run full test suite
cd testsuites/CWE416 && bash run_test.sh
```

Output is written to `results/<category>/` automatically.

---

## Example output

```
========================================
 CWE-416 Use After Free Detector
 Source  : bad_use_after_free_01.c
 Report  : results/char/bad_use_after_free_01_report_<ts>.txt
 Findings: results/char/bad_use_after_free_01_findings_<ts>.json
========================================
...
{
  "detector": "use_after_free",
  "severity": "error",
  "rule": "useAfterFree",
  "file": "bad_use_after_free_01.c",
  "line": 12,
  "col": 5,
  "varname": "data",
  "note": {
    "line": 9,
    "col": 5,
    "message": "Memory freed here"
  }
}

 Total findings : 1
 Errors         : 1
 Warnings       : 0

 Breakdown by detector:
   use_after_free            1
```

---

## Folder structure

```
SCS004_Use_After_Free/
│
├── README.md
│
├── src/
│   ├── smell_report.sh          ← single-file entry point
│   ├── smell_report_multi.sh    ← multi-file entry point
│   ├── pipeline.sh              ← stages 1–3 (srcml → srcslice → srcattributor)
│   ├── report.sh                ← cppcheck-style report formatter
│   ├── detectors/
│   │   ├── detect_use_after_free.sh
│   │   ├── detect_double_free.sh
│   │   └── detect_interprocedural_uaf.sh
│   └── lib/
│       └── write_finding.sh     ← shared JSON finding writer
│
├── testsuites/
│   └── CWE416/
│       ├── run_test.sh              ← test suite runner
│       ├── char/                    ← malloc_free_char (.c)
│       ├── int/                     ← malloc_free_int (.c)
│       ├── int64/                   ← malloc_free_int64_t (.c)
│       ├── long/                    ← malloc_free_long (.c)
│       ├── struct/                  ← malloc_free_struct (.c)
│       ├── wchar_t/                 ← malloc_free_wchar_t (.c)
│       ├── delete_array_char/       ← new_delete_array_char (.cpp)
│       ├── delete_array_class/      ← new_delete_array_class (.cpp)
│       ├── delete_array_int/        ← new_delete_array_int (.cpp)
│       ├── delete_array_int64_t/    ← new_delete_array_int64_t (.cpp)
│       ├── delete_array_long/       ← new_delete_array_long (.cpp)
│       ├── delete_array_struct/     ← new_delete_array_struct (.cpp)
│       ├── delete_array_wchar_t/    ← new_delete_array_wchar_t (.cpp)
│       ├── new_delete_char/         ← new_delete_char (.cpp)
│       ├── new_delete_class/        ← new_delete_class (.cpp)
│       ├── new_delete_int/          ← new_delete_int (.cpp)
│       ├── new_delete_int64_t/      ← new_delete_int64_t (.cpp)
│       ├── new_delete_long/         ← new_delete_long (.cpp)
│       ├── new_delete_struct/       ← new_delete_struct (.cpp)
│       ├── new_delete_wchar_t/      ← new_delete_wchar_t (.cpp)
│       ├── operator_equals/         ← operator= overload cases (.cpp)
│       ├── interprocedural/         ← cross-file UAF test cases (22a/22b pairs)
│       └── freed_pointer/           ← return-freed-pointer cases (.c)
│
├── results/                     ← generated reports and findings (by category)
│   ├── char/
│   ├── int/
│   ├── struct/
│   └── wchar_t/
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
│   ├── run_smelldetect.sh          ← SmellDetect benchmark
│   ├── compare_report.sh        ← generates comparison table
│   ├── smelldetect_results.json
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
bash evaluation/run_smelldetect.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

Latest results (`evaluation/comparison_report.txt`):

| Test Case | SmellDetect | cppcheck | Joern |
|-----------|----------|----------|-------|
| bad_use_after_free_int_01 | YES | NO | YES |
| good_use_after_free_int_01 | NO | NO | YES (FP) |
| bad_new_delete_int_01 | YES | YES | YES |
| good_new_delete_int_01 | NO | NO | YES (FP) |
| bad_return_freed_ptr_01 | YES | YES | YES |
| good_return_freed_ptr_01 | NO | NO | YES (FP) |
| bad_operator_equals_01 | YES | YES | NO |
| good_operator_equals_01 | NO | NO | NO |

**Detections (bad cases only): SmellDetect 4/4 — cppcheck 3/4 — Joern 3/4**

SmellDetect detects the malloc/free use-after-free that cppcheck misses (`bad_use_after_free_int_01`).
Joern's generic identifier-reuse query produces false positives on all `good_*` malloc/free and
new/delete cases — it cannot distinguish use-before-free from use-after-free without control flow.

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
| `docs/pipeline.md` | Three-stage pipeline, all detector queries explained |
| `docs/variants.md` | Juliet variant coverage by detector and flow type |
| `docs/known_issues.md` | Known false negatives and tool limitations |
