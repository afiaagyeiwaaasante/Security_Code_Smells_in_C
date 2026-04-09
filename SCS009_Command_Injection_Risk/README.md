# SCS009 — Command Injection Risk (CWE-78)

## Description

A **command injection risk** occurs when user-supplied data is passed directly
to an OS command execution function (`system`, `popen`, `execl`, `execlp`)
without sanitisation. An attacker who controls the command string can append
shell metacharacters (`;`, `|`, `&`, `` ` `` , `$()`) to execute arbitrary
operating system commands with the privileges of the running process.

**CWE:** [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

**Severity:** `warning [SCS009-SYSTEM | SCS009-POPEN | SCS009-EXECL]`

## Smell Pattern

**Bad — user input flows directly into OS command sink:**
```c
char data[256];
fgets(data, sizeof(data), stdin);  // source: user input
system(data);                      // FLAW: shell metacharacters not stripped
popen(data, "r");                  // FLAW: same issue with popen
```

**Good — literal command string, no user input:**
```c
system("ls -l");                   // FIX: literal command, no taint
popen("ls -l", "r");              // FIX: literal command
```

## Folder Structure

```
SCS009_Command_Injection_Risk/
├── src/
│   ├── pipeline.sh                         # Stage 1–3: srcml → srcslice → srcattributor
│   ├── smell_report.sh                     # Orchestrator: pipeline + all detectors
│   ├── report.sh                           # Human-readable report formatter
│   ├── detectors/
│   │   ├── detect_system_tainted.sh        # system() — command arg 0
│   │   ├── detect_popen_tainted.sh         # popen() — command arg 0
│   │   └── detect_execl_tainted.sh         # execl()/execlp() — path arg 0
│   └── lib/
│       └── write_finding.sh                # Shared JSON finding writer
├── testsuites/
│   └── CWE78/
│       ├── system_console/                 # Group 1 — fgets source, system() sink
│       ├── system_env/                     # Group 2 — getenv source, system() sink
│       ├── popen_console/                  # Group 3 — fgets source, popen() sink
│       ├── interprocedural/                # Group 4 — flow 22 cross-file (known FN)
│       └── cpp_class/                      # Group 5 — flow 84 C++ class (known FN)
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

| Detector | Sink function | Command arg index | Rule |
|---|---|---|---|
| `detect_system_tainted.sh` | `system` | 0 (first/only) | `SCS009-SYSTEM` |
| `detect_popen_tainted.sh` | `popen` | 0 (first, the command) | `SCS009-POPEN` |
| `detect_execl_tainted.sh` | `execl`, `execlp` | 0 (the path) | `SCS009-EXECL` |

All detectors apply a **two-part guard**:
1. A taint source (`fgets` or `getenv`) must be present in the same function block.
2. The command argument must be a `<name>` (variable), not a `<literal>` (string constant).

A finding is emitted only when both conditions hold. This eliminates the
goodG2B pattern (hardcoded literal passed to sink, even if `fgets` is present).

## Usage

### Single file

```bash
bash src/smell_report.sh testsuites/CWE78/system_console/bad_system_console_01.c
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
| True Positives (TP) | 3 | 0 | TBD |
| True Negatives (TN) | 5 | 5 | TBD |
| False Positives (FP) | 0 | 0 | TBD |
| False Negatives (FN) | 2 | 5 | TBD |
| Precision | 100% | N/A | TBD |
| Recall | 60% | 0% | TBD |
| Avg wall time | ~0.30s | ~0.00s | TBD |
| Avg peak RSS | ~14.8 MB | ~7.9 MB | TBD |

**SmellDetect** achieves 100% precision (no false positives) and 60% recall. The
two false negatives are known limitations: the interprocedural (flow 22) and
C++ class (flow 84) patterns require cross-block/cross-file taint analysis
beyond the scope of the structural detector.

**cppcheck** produces no findings for any CWE-78 test case — it has no
dedicated command injection check in version 2.19.

**Joern** results pending. The Joern query (CPG-based, argument node type
check) is expected to detect Groups 1–3 and may also detect Group 4 via
inter-procedural taint propagation.

## Documentation

- [docs/pipeline.md](docs/pipeline.md) — pipeline architecture and srcML patterns
- [docs/known_issues.md](docs/known_issues.md) — limitations and edge cases
- [docs/variants.md](docs/variants.md) — CWE-78 variant analysis and group breakdown
