# SCS008 — Missing Format Specifier (CWE-134)

## Description

A **missing format specifier** occurs when a variable — whose value may be
externally controlled — is passed directly as the format string argument to a
`printf`-family function instead of as a data argument after a literal format
string. An attacker who controls the format string can inject format directives
(`%n`, `%x`, `%s`, etc.) to read from or write to arbitrary memory locations.

**CWE:** [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)

**Severity:** `warning [SCS008-PRINTF | SCS008-FPRINTF | SCS008-SYSLOG]`

## Smell Pattern

**Bad — variable used directly as format argument:**
```c
char data[100];
fgets(data, sizeof(data), stdin);
printf(data);               // FLAW: attacker controls format directives
fprintf(stderr, data);      // FLAW: same issue with fprintf
syslog(LOG_INFO, data);     // FLAW: same issue with syslog
```

**Good — literal format string, variable as data argument:**
```c
printf("%s\n", data);       // FIX: data treated as a value, not a format
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
│       ├── interprocedural/             # Group 4 — flow 22 two-file source/sink
│       └── cpp_class/                   # Group 5 — flow 84 C++ class destructor
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

All detectors scan the annotated srcML XML for format-function calls and check
whether the format argument is a `<literal>` (literal string) or a `<name>`
(variable reference). A literal format string is the guard.

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

## Evaluation Results

| | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| True Positives (TP) | 5 | 0 | 5 |
| True Negatives (TN) | 5 | 5 | 5 |
| False Positives (FP) | 0 | 0 | 0 |
| False Negatives (FN) | 0 | 5 | 0 |
| Precision | 100% | N/A | 100% |
| Recall | 100% | 0% | 100% |
| Avg wall time | 0.301s | 0.010s | 3.684s |
| Avg peak RSS | 14.8 MB | 8.0 MB | 428.9 MB |

**cppcheck** misses all cases — it requires type-mismatch evidence that is only
available at link time or with explicit format-checking attributes.
**Joern** detects correctly (literal vs. identifier node type is preserved in
the CPG), but at ~12× the runtime and ~29× the memory of SmellDetect.

## Documentation

- [docs/pipeline.md](docs/pipeline.md) — pipeline architecture and srcML patterns
- [docs/known_issues.md](docs/known_issues.md) — limitations and edge cases
- [docs/variants.md](docs/variants.md) — CWE-134 variant analysis and group breakdown
