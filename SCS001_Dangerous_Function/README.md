# SCS001 — Dangerous Function Use

**CWE:** CWE-242 Use of Inherently Dangerous Function
**Severity:** warning
**Rule ID:** `dangerousFunction`

## Description

This security code smell refers to the use of inherently dangerous C standard
library functions that are known to be unsafe due to the absence of bounds
checking or input validation mechanisms. These functions can lead to:

- Buffer overflows
- Stack corruption
- Arbitrary code execution
- Denial of service

## Why this is a Problem

Certain legacy C functions do not enforce input size constraints. When used
improperly, they allow writing beyond allocated memory boundaries.

Currently covers: `gets()`

`gets()` reads from stdin into a buffer with no bounds check. Regardless of
buffer size, a sufficiently long input will overflow it. It was deprecated in
C99 and removed in C11. It must always be replaced with `fgets(buf, size, stdin)`.

**Example (bad):**
```c
char buf[64];
gets(buf);          /* FLAW: no bounds check — any input > 63 chars overflows */
```

**Example (good):**
```c
char buf[64];
fgets(buf, sizeof(buf), stdin);   /* FIX: bounded read */
```

## Security Classification

CWE ID: 242
Risk Level: High
Category: Memory Safety Violation

---

## Project structure

```
SCS001_Dangerous_Function/
├── src/
│   ├── smell_report.sh           — run detector on a single file
│   ├── smell_report_multi.sh     — run detector on multiple files combined
│   ├── pipeline.sh               — srcml parse stage
│   ├── detectors/
│   │   └── detect_dangerous_function.sh
│   └── lib/
│       └── write_finding.sh      — shared JSON finding writer
├── testsuites/
│   └── CWE242/
│       ├── gets/
│       │   ├── bad_gets_01.c     — direct gets() call (bad)
│       │   └── good_gets_01.c    — fgets() replacement (good)
│       ├── interprocedural/
│       │   ├── bad_gets_interprocedural_62a.c   — caller (gets hidden in callee)
│       │   └── bad_gets_interprocedural_62b.c   — callee (gets called here)
│       ├── testsuitesupport/
│       │   └── std_testcase.h
│       └── run_test.sh
├── cppcheck/
│   ├── scripts/run_cppcheck.sh   — cppcheck benchmark
│   └── results/
├── joern/
│   ├── scripts/run_joern.sh      — Joern benchmark
│   └── results/
├── evaluation/
│   ├── run_our_tool.sh           — our tool benchmark
│   ├── compare_report.sh         — generates comparison table
│   ├── our_tool_results.json
│   └── comparison_report.txt
└── doc/
    ├── pipeline.md               — pipeline stages and query details
    ├── known_issues.md           — limitations and edge cases
    └── variants.md               — other dangerous functions and extension points
```

---

## Running the detector

**Single file:**
```bash
bash src/smell_report.sh testsuites/CWE242/gets/bad_gets_01.c
```

**Multi-file (interprocedural):**
```bash
bash src/smell_report_multi.sh \
    testsuites/CWE242/interprocedural/bad_gets_interprocedural_62a.c \
    testsuites/CWE242/interprocedural/bad_gets_interprocedural_62b.c
```

**Full test suite:**
```bash
cd testsuites/CWE242 && bash run_test.sh
```

---

## Tool comparison

Run all three benchmarks then generate the report:

```bash
bash evaluation/run_our_tool.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

Latest results (`evaluation/comparison_report.txt`):

| Test Case | Our Tool | cppcheck | Joern |
|-----------|----------|----------|-------|
| bad_gets_01 | 0.11s / 14.7 MB / YES | 0.01s / 7.9 MB / YES | 3.96s / 344 MB / YES |
| good_gets_01 | 0.05s / 14.7 MB / NO | 0.00s / 7.9 MB / NO | 3.40s / 357 MB / NO |
| bad_gets_interprocedural_62 | 0.07s / 14.6 MB / YES | 0.00s / 8.0 MB / YES | 3.28s / 413 MB / YES |

---

## Requirements

- `srcml` — source parsing and srcQL queries
- `xmllint` — XPath extraction from srcQL results
- `cppcheck` — comparison benchmark only
- `joern` — comparison benchmark only
- `python3` — summary and report generation

---

## Documentation

| Document | Contents |
|----------|---------|
| `doc/pipeline.md` | Pipeline stages, srcQL query, XPath extraction |
| `doc/known_issues.md` | Known limitations and edge cases |
| `doc/variants.md` | Other dangerous functions and UNION query extensions |