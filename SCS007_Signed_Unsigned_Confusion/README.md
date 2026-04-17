# SCS007 — Signed/Unsigned Confusion (CWE-195)

## Description

A **signed-to-unsigned conversion error** occurs when a signed integer (which
may hold negative values) is implicitly converted to an unsigned type. In C and
C++, passing a negative `int` to a function that expects a `size_t` argument
causes the value to wrap around to a very large positive number. Applied to
memory operations (`malloc`, `memcpy`, `strncpy`), this can lead to massive
heap allocations or unbounded copies — enabling heap overflow or
denial-of-service.

**CWE:** [CWE-195: Signed to Unsigned Conversion Error](https://cwe.mitre.org/data/definitions/195.html)

## Vulnerability vs. Smell Classification

SCS007 findings are classified at detection time based on whether a taint source
(`fscanf`, `scanf`, `fgets`, `getenv`) appears in the same function scope as the
signed-to-unsigned sink.

| Condition                           | Severity  | Classification  |
|-------------------------------------|-----------|-----------------|
| Taint source present in scope       | `error`   | `vulnerability` |
| No taint source (constant/internal) | `warning` | `smell`         |

**Why a taint source makes it a vulnerability:** If attacker-controlled input
flows into a signed integer that is then passed to `malloc`, `memcpy`, or
`strncpy` without a positivity guard, a negative value wraps to `SIZE_MAX`,
resulting in a massive allocation or unbounded memory operation. This is
directly exploitable via crafted input (e.g., `fscanf(stdin, "%d", &data)`
followed by `malloc(data)`).

**Why the untainted form is a smell:** When the value comes from a constant or
internal computation, the signed integer is unlikely to be negative as written.
The pattern is structurally fragile — replacing the constant with unvalidated
user input would immediately introduce a vulnerability. Maps to CWE-195.

## Folder Structure

```
SCS007_Signed_Unsigned_Confusion/
├── src/
│   ├── smell_report.sh                 # Orchestrator: pipeline + all detectors
│   ├── report.sh                       # Human-readable report formatter
│   ├── detectors/
│   │   ├── detect_signed_malloc.sh
│   │   ├── detect_signed_memcpy.sh
│   │   └── detect_signed_strncpy.sh
├── testsuites/
│   └── CWE195/
│       ├── malloc_size/                # Signed int as malloc size argument
│       ├── memcpy_count/               # Signed int as memcpy/memmove count
│       ├── strncpy_count/              # Signed int as strncpy count
│       ├── interprocedural/            # Flow 22 — two-file source/sink
│       ├── cpp_class/                  # Flow 84 — ctor/dtor on heap (C++)
│       └── run_test.sh                 # Full test suite runner
├── cppcheck/
│   ├── scripts/run_cppcheck.sh
│   └── results/
├── joern/
│   ├── scripts/run_joern.sh
│   └── results/
├── evaluation/
│   ├── run_smelldetect.sh
│   ├── compare_report.sh
│   └── results/
├── docs/
│   ├── pipeline.md
│   ├── known_issues.md
│   ├── query_comparison.md
│   └── variants.md
└── README.md
```

## Detectors

| Detector                   | Sink                    | Guard checked                      |
|----------------------------|-------------------------|------------------------------------|
| `detect_signed_malloc.sh`  | `malloc(data)`          | Positivity check (`data > 0`) in `<condition>` |
| `detect_signed_memcpy.sh`  | `memcpy(d, s, data)` / `memmove(d, s, data)` | Positivity check in `<condition>` |
| `detect_signed_strncpy.sh` | `strncpy(d, s, data)`   | Positivity check in `<condition>` |

All detectors scan the annotated srcML XML for a signed integer variable used as
the size/count argument, then check whether any `<condition>` in the same
function block contains a positivity guard on that variable. Taint co-occurrence
(presence of `fscanf`/`scanf`/`fgets`/`getenv`) escalates the finding from
`warning/smell` to `error/vulnerability`.

## Usage

### Single file

```bash
bash src/smell_report.sh testsuites/CWE195/malloc_size/bad_malloc_size_01.c
```

### Full test suite

```bash
bash testsuites/CWE195/run_test.sh
```

### Comparison benchmarks

```bash
bash evaluation/run_smelldetect.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

## Test Results

**SmellDetect — 13/13 test cases (100%)**

`bad_*` cases are expected to produce at least one finding (any severity).
`good_*` cases are expected to produce zero findings.
`smell_*` cases are expected to produce a finding with `severity=warning` and `classification=smell`.

| Group             | Bad | Good | Smell | TP | TN | SMELL-TP | FP | FN |
|-------------------|-----|------|-------|----|----|----------|----|-----|
| malloc_size       | 1   | 1    | 1     | 1  | 1  | 1        | 0  | 0  |
| memcpy_count      | 1   | 1    | 1     | 1  | 1  | 1        | 0  | 0  |
| strncpy_count     | 1   | 1    | 1     | 1  | 1  | 1        | 0  | 0  |
| interprocedural†  | 1   | 1    | —     | 1  | 1  | —        | 0  | 0  |
| cpp_class         | 1   | 1    | —     | 1  | 1  | —        | 0  | 0  |
| **Total**         | **5** | **5** | **3** | **5** | **5** | **3** | **0** | **0** |

† Only the 22b (sink) file is tested. The 22a (source) file contains no sink and
cannot be detected by single-file analysis. See `docs/known_issues.md`.

**Benchmark comparison (SmellDetect vs cppcheck vs Joern):**

| Metric        | SmellDetect | cppcheck | Joern   |
|---------------|-------------|----------|---------|
| Precision     | 100%        | N/A      | 100%    |
| Recall        | 100%        | 0%       | 100%    |
| Avg time      | 0.307s      | 0.010s   | 3.631s  |
| Avg memory    | 14.7 MB     | 8.0 MB   | 444.2 MB|

cppcheck misses all cases (no signed-to-unsigned rule for these patterns).
Joern detects the same set with no false positives, but uses ~30× more memory
and ~12× more time per file.

## Detection Pattern

**Vulnerability (tainted, no positivity guard → `error/vulnerability`):**
```c
int data;
fscanf(stdin, "%d", &data);     // taint source — attacker-controlled
void *p = malloc(data);         // FLAW: negative data wraps to SIZE_MAX
```

**Smell (untainted, no positivity guard → `warning/smell`):**
```c
int data = 42;                  // internal constant — always positive
void *p = malloc(data);         // SMELL: structurally fragile, safe as written
```

**Good (positivity guard → no finding):**
```c
if (data > 0) {
    void *p = malloc(data);     // guarded — safe
}
```

## Known Limitations

- Interprocedural taint tracking (22a → 22b) requires multi-file analysis (KI-001)
- Numeric positivity literals (e.g., `data > 0`) must appear as a `<condition>`
  element; complex guard expressions may be missed (KI-002)

See [docs/known_issues.md](docs/known_issues.md) for full details.

## Documentation

- [docs/pipeline.md](docs/pipeline.md) — pipeline architecture and srcML patterns
- [docs/known_issues.md](docs/known_issues.md) — false positives, false negatives, limitations
- [docs/variants.md](docs/variants.md) — CWE-195 scenario and variant coverage
- [docs/query_comparison.md](docs/query_comparison.md) — srcQL query design notes
