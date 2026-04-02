# SCS003 — Missing Null Check (CWE-476)

## Description

A **Missing Null Check** occurs when a pointer is dereferenced without first
verifying that it is not `NULL`. This is classified as **CWE-476: NULL Pointer
Dereference** and can lead to program crashes, denial of service, or exploitable
memory corruption.

This detector uses a three-stage static analysis pipeline (srcml → srcslice →
srcattributor) followed by six structural detectors built with srcQL and xmllint.

---

## Detectors

| # | Detector | Pattern | Severity |
|---|---|---|---|
| 1 | `binary_if` | `&` instead of `&&` in null-check condition | error |
| 2 | `interprocedural` | callee dereferences param; caller passes NULL or unguarded ptr | error / warning |
| 3 | `null_deref` | `ptr = NULL` then `ptr->field` or `ptr[idx]`, no guard | error |
| 4 | `missing_guard` | unguarded `->` or `[]` dereference, no null check in function | warning |
| 5 | `deref_after_check` | `if(ptr == NULL) { *ptr }` — deref inside null-confirmed branch | error |
| 6 | `check_after_deref` | `*ptr` then `if(ptr != NULL)` — guard placed after dereference | warning |

---

## Quick start

```bash
# Single file
bash src/smell_report.sh testsuites/CWE476/binary_if/bad_binary_if_01.c

# Multi-file (cross-file interprocedural)
bash src/smell_report_multi.sh \
    testsuites/CWE476/interprocedural/bad_char_interprocedural_22a.c \
    testsuites/CWE476/interprocedural/bad_char_interprocedural_22b.c

# Run full test suite
cd testsuites/CWE476 && bash run_test.sh
```

Output is written to `results/<category>/` automatically.

---

## Example output

```
========================================
 CWE-476 NULL Pointer Dereference Detector
 Source  : bad_binary_if_01.c
 Report  : results/binary_if/bad_binary_if_01_report_<ts>.txt
 Findings: results/binary_if/bad_binary_if_01_findings_<ts>.json
========================================
...
{
  "detector": "binary_if",
  "severity": "error",
  "rule": "nullPointer",
  "file": "bad_binary_if_01.c",
  "line": 22,
  "col": 29,
  "varname": "ptr",
  "note": {
    "line": 19,
    "col": 5,
    "message": "Assignment 'ptr=NULL', assigned value is 0"
  }
}

 Total findings : 1
 Errors         : 1
 Warnings       : 0

 Breakdown by detector:
   binary_if                 1
```

---

## Folder structure

```
SCS003_Missing_Null_Check/
│
├── README.md
│
├── src/
│   ├── smell_report.sh          ← single-file entry point
│   ├── smell_report_multi.sh    ← multi-file entry point
│   ├── pipeline.sh              ← stages 1–3 (srcml → srcslice → srcattributor)
│   ├── report.sh                ← cppcheck-style report formatter
│   ├── detectors/
│   │   ├── detect_binary_if.sh
│   │   ├── detect_interprocedural.sh
│   │   ├── detect_null_deref.sh
│   │   ├── detect_missing_guard.sh
│   │   ├── detect_deref_after_check.sh
│   │   └── detect_check_after_deref.sh
│   └── lib/
│       └── write_finding.sh     ← shared JSON finding writer
│
├── testsuites/
│   └── CWE476/
│       ├── run_test.sh          ← test suite (25 cases, all passing)
│       ├── binary_if/           ← Detector 1 test cases
│       ├── interprocedural/     ← Detector 2 test cases
│       ├── deref_no_check/      ← Detectors 3 & 4 test cases
│       ├── char/                ← Detectors 3 & 4 (array index)
│       ├── after_check/         ← Detector 5 test cases
│       ├── check_after_deref/   ← Detector 6 test cases
│       ├── struct/              ← NULL propagation variant test cases
│       └── testsuitesupport/    ← Juliet shared headers
│
├── results/                     ← generated reports and findings (by category)
│   ├── binary_if/
│   ├── char/
│   ├── deref_no_check/
│   ├── interprocedural/
│   ├── after_check/
│   ├── check_after_deref/
│   └── struct/
│
└── docs/
    ├── pipeline.md              ← pipeline architecture and detector queries
    ├── variants.md              ← Juliet variant coverage and test status
    └── known_issues.md          ← false negatives and limitations
```

---

## Requirements

- `srcml` — srcML toolkit
- `srcslice` — data-flow slice analysis
- `srcattributor` — merges slice data into srcML XML
- `xmllint` — XPath extraction from XML
- `python3` — summary report generation

---

## Documentation

| Doc | Contents |
|---|---|
| `docs/pipeline.md` | Three-stage pipeline, all 6 detector queries explained |
| `docs/variants.md` | Juliet variant coverage by detector and flow type |
| `docs/known_issues.md` | Known false negatives and tool limitations |
