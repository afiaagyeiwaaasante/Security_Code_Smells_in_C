# SCS008 — Missing Format Specifier (CWE-134)

## Description

A **missing format specifier** occurs when a variable — whose value may be
externally controlled — is passed directly as the format string argument to a
`printf`-family function instead of as a data argument after a literal format
string. An attacker who controls the format string can inject format directives
(`%n`, `%x`, `%s`, etc.) to read from or write to arbitrary memory locations.

**CWE:** [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)

**Severity:** `warning [SCS008-PRINTF | SCS008-FPRINTF | SCS008-SYSLOG]`

## Vulnerability vs. Smell Classification

SCS008 findings are classified at detection time based on whether a taint source
(`fgets`, `getenv`, `scanf`, `fscanf`) appears in the same function scope as the
unguarded format call.

| Condition                                   | Severity  | Classification  |
|---------------------------------------------|-----------|-----------------|
| Taint source present in scope               | `error`   | `vulnerability` |
| No taint source (interprocedural / unknown) | `warning` | `smell`         |

**Why a taint source makes it a vulnerability:** If an attacker-controlled value
reaches the format position, the `%n` specifier enables arbitrary memory writes
and `%s`/`%x` directives leak stack contents. The co-occurrence of `fgets`/`getenv`
confirms a user-controlled value is in scope. Maps to CWE-134.

**Why the taint-invisible form is a smell:** When no taint source is visible in the
same block (e.g., the tainted value arrives via a function argument or global), the
pattern is structurally fragile — the format argument is not a literal, and any
future wiring of user input to that argument would be immediately exploitable.
`cppcheck` flags this as `warning [formatString]`.

## Smell Pattern

**Vulnerability (taint source present → `error/vulnerability`):**
```c
char data[100];
fgets(data, sizeof(data), stdin);  // taint source — attacker-controlled
printf(data);                       // FLAW: %n writes, %s/%x leaks stack
fprintf(stderr, data);              // FLAW: same issue
syslog(LOG_INFO, data);             // FLAW: same issue
```

**Smell (no taint in scope → `warning/smell`):**
```c
extern char *get_message(void);     // taint origin not visible here
printf(get_message());              // SMELL: non-literal format, taint unknown
```

**Good — literal format string:**
```c
printf("%s\n", data);               // FIX: data is a value, not a format
fprintf(stderr, "%s\n", data);
syslog(LOG_INFO, "%s", data);
```

## Folder Structure

```
SCS008_Missing_Format_Specifier/
├── src/
│   ├── pipeline.sh                      # Stage 1–3: srcml → srcslice → srcattributor
│   ├── smell_report.sh                  # Orchestrator: pipeline + all detectors
│   ├── report.sh                        # Human-readable report formatter
│   ├── detectors/
│   │   ├── detect_printf_direct.sh      # printf/vprintf — format arg 0
│   │   ├── detect_fprintf_direct.sh     # fprintf/vfprintf — format arg 1
│   │   └── detect_syslog_direct.sh      # syslog — format arg 1
│   └── lib/
│       └── write_finding.sh             # Shared JSON finding writer
├── testsuites/
│   └── CWE134/
│       ├── printf_direct/               # Group 1 — console source, printf sink
│       ├── fprintf_direct/              # Group 2 — file source, fprintf sink
│       ├── env_format/                  # Group 3 — getenv source, printf sink
│       ├── interprocedural/             # Group 4 — flow 22 two-file source/sink (warning/smell on 22b)
│       └── cpp_class/                   # Group 5 — flow 84 C++ class ctor/dtor split
├── cppcheck/
│   ├── scripts/run_cppcheck.sh
│   └── results/
├── joern/
│   ├── scripts/run_joern.sh
│   └── results/
├── evaluation/
│   ├── run_smelldetect.sh
│   ├── compare_report.sh
│   └── comparison_report.txt
├── docs/
│   ├── pipeline.md
│   ├── known_issues.md
│   └── variants.md
└── README.md
```

## Detectors

| Detector | Sink functions | Format arg index | Rule |
|---|---|---|---|
| `detect_printf_direct.sh` | `printf`, `vprintf` | 0 (first) | `SCS008-PRINTF` |
| `detect_fprintf_direct.sh` | `fprintf`, `vfprintf` | 1 (second, after stream) | `SCS008-FPRINTF` |
| `detect_syslog_direct.sh` | `syslog` | 1 (second, after priority) | `SCS008-SYSLOG` |

All detectors use a two-stage approach:
- **Stage 1 (srcQL):** Scopes to function bodies; checks whether the format
  argument is a `<literal>` (safe) or `<name>` (variable). If a taint source is
  also present → `error/vulnerability`; otherwise → `warning/smell`.
- **Stage 2 (XPath fallback):** Covers destructor/constructor blocks (not matched
  by srcQL). Stage 2b additionally handles the ctor/dtor split: `printf` sink in
  destructor with `fgets`/`getenv` in sibling constructor → `error/vulnerability`.

## Usage

### Single file

```bash
bash src/smell_report.sh testsuites/CWE134/printf_direct/bad_printf_direct_01.c
```

### Comparison benchmarks

```bash
bash evaluation/run_smelldetect.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

## Test Results

**SmellDetect — 10/10 test cases (100%)**

`bad_*` cases are expected to produce at least one finding (any severity).
`good_*` cases are expected to produce zero findings.

| Group           | Bad | Good | TP | TN | FP | FN | Severity |
|-----------------|-----|------|----|----|----|-----|---------|
| printf_direct   | 1   | 1    | 1  | 1  | 0  | 0  | error/vulnerability |
| fprintf_direct  | 1   | 1    | 1  | 1  | 0  | 0  | error/vulnerability |
| env_format      | 1   | 1    | 1  | 1  | 0  | 0  | error/vulnerability |
| interprocedural | 1   | 1    | 1  | 1  | 0  | 0  | warning/smell (no taint in 22b) |
| cpp_class       | 1   | 1    | 1  | 1  | 0  | 0  | error/vulnerability (ctor/dtor split) |
| **Total**       | **5** | **5** | **5** | **5** | **0** | **0** | |

### Benchmark comparison (SmellDetect vs cppcheck vs Joern)

| Metric        | SmellDetect | cppcheck | Joern    |
|---------------|-------------|----------|----------|
| Precision     | 100%        | N/A      | 100%     |
| Recall        | 100%        | 0%       | 100%     |
| Avg time      | ~0.30s      | ~0.01s   | ~3.68s   |
| Avg memory    | ~14.8 MB    | ~8.0 MB  | ~428.9 MB|

**cppcheck** misses all cases — it requires type-mismatch evidence only available
at link time or with explicit format-checking attributes (`__attribute__((format))`).
**Joern** detects all cases correctly (literal vs. identifier node type is preserved
in the CPG), but at ~12× the runtime and ~29× the memory of SmellDetect.

## Known Limitations

- KI-001 (resolved): interprocedural 22b now fires `warning/smell`
- KI-002 (resolved): C++ ctor/dtor split now detected via Stage 2b XPath
- `snprintf`/`sprintf` not yet covered (KI-007)
- Wrapper functions around printf not detected (KI-003)
- No path sensitivity — co-occurrence model only (KI-006)

See [docs/known_issues.md](docs/known_issues.md) for full details.

## Documentation

- [docs/pipeline.md](docs/pipeline.md) — pipeline architecture and srcML patterns
- [docs/known_issues.md](docs/known_issues.md) — limitations and edge cases
- [docs/variants.md](docs/variants.md) — CWE-134 variant analysis and group breakdown
