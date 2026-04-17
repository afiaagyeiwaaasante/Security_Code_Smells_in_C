# SCS006 — Integer Overflow Risk (CWE-190)

## Description

An **integer overflow** occurs when the result of an arithmetic operation exceeds
the maximum value representable by the integer type, causing the value to wrap
around silently. In C and C++, signed integer overflow is undefined behaviour;
unsigned overflow wraps to zero. Both can lead to buffer overflows, incorrect
control flow, or security vulnerabilities.

**CWE:** [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)

## Vulnerability vs. Smell Classification

SCS006 findings are classified at detection time based on whether a taint source
(`fscanf`, `scanf`, `fgets`, `getenv`) appears in the same function scope as the
unchecked arithmetic expression.

| Condition                          | Severity  | Classification  |
|------------------------------------|-----------|-----------------|
| Taint source present in scope      | `error`   | `vulnerability` |
| No taint source (constant/internal)| `warning` | `smell`         |

**Why a taint source makes it a vulnerability:** If attacker-controlled input
reaches the arithmetic operand without a bounds check, the value can be made
arbitrarily large, causing wrap-around. This is directly exploitable via
crafted input (e.g., `fscanf(stdin, "%d", &data)` followed by `data * 2`).

**Why the untainted form is a smell:** When the value comes from a constant or
internal computation, no overflow occurs as written. The pattern is structurally
fragile — replacing the constant with unvalidated user input would immediately
introduce a vulnerability. `cppcheck` flags this as `warning [integerOverflow]`.
Maps to CWE-190.

## Folder Structure

```
SCS006_Integer_Overflow_Risk/
├── src/
│   ├── pipeline.sh                     # Stage 1–3: srcml → srcslice → srcattributor
│   ├── smell_report.sh                 # Orchestrator: pipeline + all detectors
│   ├── report.sh                       # Human-readable report formatter
│   ├── detectors/
│   │   ├── detect_unchecked_multiply.sh
│   │   ├── detect_unchecked_add.sh
│   │   └── detect_unchecked_increment.sh
│   └── lib/
│       └── write_finding.sh            # Shared JSON finding writer
├── testsuites/
│   └── CWE190/
│       ├── add/                        # S01 — addition overflow
│       ├── multiply/                   # S02 — multiplication overflow
│       ├── square/                     # S03 — squaring overflow
│       ├── postinc/                    # S04 — postfix increment overflow
│       ├── preinc/                     # S05 — prefix increment overflow
│       ├── cpp_virtual_ref/            # Flow 81 — virtual method via reference
│       ├── cpp_virtual_ptr/            # Flow 82 — virtual method via pointer
│       ├── cpp_ctor_stack/             # Flow 83 — ctor/dtor on stack
│       ├── cpp_ctor_heap/              # Flow 84 — ctor/dtor on heap
│       ├── interprocedural/            # Flow 22 — two-file source/sink
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
│   └── variants.md
└── README.md
```

## Detectors

| Detector                       | Targets                  | Guard checked                        |
|--------------------------------|--------------------------|--------------------------------------|
| `detect_unchecked_multiply.sh` | `data * value`           | `INT_MAX` / `CHAR_MAX` in `<condition>` |
| `detect_unchecked_add.sh`      | `data + value`           | `INT_MAX` / `UINT_MAX` in `<condition>` |
| `detect_unchecked_increment.sh`| `data++` / `++data`      | `INT_MAX` in `<condition>`           |

All detectors scan the annotated srcML XML for arithmetic operators and check
whether any `<condition>` element in the same function/destructor/constructor
block contains a symbolic MAX constant.

## Usage

### Single file

```bash
bash src/smell_report.sh testsuites/CWE190/multiply/bad_int_multiply_01.c
```

### Full test suite

```bash
bash testsuites/CWE190/run_test.sh
```

### Comparison benchmarks

```bash
bash evaluation/run_smelldetect.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

## Test Results

**SmellDetect — 26/26 test cases (100%)**

`bad_*` cases are expected to produce at least one finding (any severity).
`good_*` cases are expected to produce zero findings.
`smell_*` cases are expected to produce a finding with `severity=warning` and `classification=smell`.

| Group           | Bad | Good | Smell | TP | TN | SMELL-TP | FP | FN |
|-----------------|-----|------|-------|----|----|----------|----|-----|
| add             | 2   | 2    | 1     | 2  | 2  | 1        | 0  | 0  |
| multiply        | 1   | 1    | 1     | 1  | 1  | 1        | 0  | 0  |
| square          | 2   | 2    | 1     | 2  | 2  | 1        | 0  | 0  |
| postinc         | 1   | 1    | 1     | 1  | 1  | 1        | 0  | 0  |
| preinc          | 1   | 1    | —     | 1  | 1  | —        | 0  | 0  |
| cpp_virtual_ref | 1   | 1    | —     | 1  | 1  | —        | 0  | 0  |
| cpp_virtual_ptr | 1   | 1    | —     | 1  | 1  | —        | 0  | 0  |
| cpp_ctor_stack  | 1   | 1    | —     | 1  | 1  | —        | 0  | 0  |
| cpp_ctor_heap   | 1   | 1    | —     | 1  | 1  | —        | 0  | 0  |
| **Total**       | **11** | **11** | **4** | **11** | **11** | **4** | **0** | **0** |

**Benchmark comparison (SmellDetect vs cppcheck vs Joern):**

| Metric        | SmellDetect | cppcheck | Joern   |
|---------------|-------------|----------|---------|
| Precision     | 100%        | N/A      | 50%     |
| Recall        | 100%        | 0%       | 100%    |
| Avg time      | 0.283s      | 0.010s   | 3.660s  |
| Avg memory    | 14.7 MB     | 7.9 MB   | 423.4 MB|

cppcheck misses all cases (no integerOverflow rule for these patterns).
Joern detects all bad_ cases but produces false positives on good_ cases (50% precision).

## Detection Pattern

**Vulnerability (tainted, no guard → `error/vulnerability`):**
```c
int data;
fscanf(stdin, "%d", &data);     // taint source — attacker-controlled
int result = data * 2;          // FLAW: overflow if data > INT_MAX / 2
```

**Smell (untainted, no guard → `warning/smell`):**
```c
int data = rand() % 100;        // internal source — not attacker-controlled
int result = data * 2;          // SMELL: structurally fragile, safe as written
```

**Good (guarded → no finding):**
```c
if (data <= (INT_MAX / 2)) { int result = data * 2; }
if (data < CHAR_MAX) { char result = data + 1; }
if (data < INT_MAX) { data++; }
```

## Known Limitations

- Loop increment (`i++`) inside a `for` loop is flagged as unchecked (KI-006)
- Numeric guard literals (e.g., `2147483647`) not matched (KI-002)
- Interprocedural flows require multi-file analysis (KI-001)

See [docs/known_issues.md](docs/known_issues.md) for full details.

## Documentation

- [docs/pipeline.md](docs/pipeline.md) — pipeline architecture and srcML patterns
- [docs/known_issues.md](docs/known_issues.md) — false positives, false negatives, limitations
- [docs/variants.md](docs/variants.md) — CWE-190 scenario and variant coverage
