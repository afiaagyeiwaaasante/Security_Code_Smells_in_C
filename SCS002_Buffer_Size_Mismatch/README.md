# SCS002 — Buffer Size Mismatch

**CWE:** CWE-680 Integer Overflow to Buffer Overflow
**Severity:** warning
**Rule ID:** `bufferSizeMismatch`

## Description

This smell occurs when `malloc` is called with a multiplication expression as
the size argument — e.g. `malloc(n * sizeof(int))`. If `n` is large enough,
`n * sizeof(int)` wraps around to a small value due to integer overflow,
causing malloc to allocate far less memory than intended. Any subsequent write
into that buffer overflows it.

The pattern is an indicator that a developer should review whether `n` is
bounded. It may or may not be exploitable depending on the source of `n`.

**Example (bad):**
```c
int *p = (int *)malloc(n * sizeof(int));   /* SMELL: n * sizeof may overflow */
```

**Example (good):**
```c
int *p = (int *)calloc((size_t)n, sizeof(int));  /* FIX: calloc checks overflow internally */
```

## Why This Is a Smell

`malloc(n * sizeof(T))` is not exploitable as currently written — overflow only occurs if `n` is attacker-controlled and unbounded. The pattern is structurally fragile: add one call that reads `n` from user input without a bounds check and the allocation silently underflows, enabling a heap overflow on the subsequent write. `cppcheck` does not flag this pattern.

## Security Classification

CWE ID: 680
Risk Level: High
Category: Memory Safety Violation

---

## Project structure

```
SCS002_Buffer_Size_Mismatch/
├── src/
│   ├── smell_report.sh           — run detector on a single file
│   ├── pipeline.sh               — srcml parse stage
│   ├── detectors/
│   │   └── detect_buffer_size.sh
│   └── lib/
│       └── write_finding.sh      — shared JSON finding writer
├── testsuites/
│   └── CWE680/
│       ├── malloc/
│       │   ├── bad_malloc_01.c   — malloc(n * sizeof) (bad)
│       │   └── good_malloc_01.c  — calloc(n, sizeof) (good)
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
│   ├── run_smelldetect.sh           — SmellDetect benchmark
│   ├── compare_report.sh         — generates comparison table
│   └── smelldetect_results.json
└── doc/
    ├── pipeline.md
    ├── known_issues.md
    └── variants.md
```

---

## Running the detector

**Single file:**
```bash
bash src/smell_report.sh testsuites/CWE680/malloc/bad_malloc_01.c
```

**Full test suite:**
```bash
cd testsuites/CWE680 && bash run_test.sh
```

---

## Tool comparison

```bash
bash evaluation/run_smelldetect.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

**Note:** cppcheck does not have a specific check for `malloc(n * sizeof(T))`
integer overflow. It will not detect this smell. This is a key differentiator
demonstrating coverage SmellDetect provides beyond cppcheck.

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
| `doc/variants.md` | realloc/memcpy variants and UNION query extensions |