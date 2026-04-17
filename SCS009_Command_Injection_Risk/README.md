# SCS009 — Command Injection Risk (CWE-78)

## Description

A **command injection risk** occurs when user-supplied data is passed directly
to an OS command execution function (`system`, `popen`, `execl`, `execlp`)
without sanitisation. An attacker who controls the command string can append
shell metacharacters (`;`, `|`, `&`, `` ` `` , `$()`) to execute arbitrary
operating system commands with the privileges of the running process.

**CWE:** [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

**Severity:** `warning [SCS009-SYSTEM | SCS009-POPEN | SCS009-EXECL]`

## Vulnerability vs. Smell Classification

SCS009 findings are classified at detection time based on whether a taint source
(`fgets`, `getenv`) appears in the same function scope as the unguarded sink call.

| Condition                                   | Severity  | Classification  |
|---------------------------------------------|-----------|-----------------|
| Taint source present in scope               | `error`   | `vulnerability` |
| No taint source (interprocedural / unknown) | `warning` | `smell`         |

**Why a taint source makes it a vulnerability:** Shell metacharacters (`;`, `|`,
`&`, `` ` ``, `$()`) in the argument to `system`/`popen`/`execl` allow arbitrary
command execution with the process's privileges. The co-occurrence of `fgets`/
`getenv` confirms a user-controlled value is in scope. Maps to CWE-78.

**Why the taint-invisible form is a smell:** When no taint source is visible in the
same block (e.g., the tainted value arrives via a function argument or global),
the pattern is structurally fragile — a non-literal command argument with unknown
provenance. `cppcheck` flags tainted `system()` calls as `error [commandInjection]`
when `--enable=all` is used.

## Smell Pattern

**Vulnerability (taint source present → `error/vulnerability`):**
```c
char data[256];
fgets(data, sizeof(data), stdin);  // taint source — attacker-controlled
system(data);                       // FLAW: shell metacharacters not stripped
popen(data, "r");                   // FLAW: same issue
```

**Smell (no taint in scope → `warning/smell`):**
```c
extern char *get_command(void);     // taint origin not visible here
system(get_command());              // SMELL: non-literal command, taint unknown
```

**Good — literal command string:**
```c
system("ls -l");                    // FIX: literal command, no taint
popen("ls -l", "r");               // FIX: literal command
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
│       ├── interprocedural/                # Group 4 — flow 22 cross-file (warning/smell on 22b)
│       └── cpp_class/                      # Group 5 — flow 84 C++ class ctor/dtor split
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

All detectors use a two-stage approach:
- **Stage 1 (srcQL):** Scopes to function bodies; checks whether the command
  argument is a `<literal>` (safe) or `<name>` (variable). If a taint source
  (`fgets`/`getenv`) is also present → `error/vulnerability`; otherwise →
  `warning/smell`. This eliminates the goodG2B pattern (literal passed to sink
  even if `fgets` is present) while still flagging taint-invisible non-literals.
- **Stage 2 (XPath fallback):** Covers destructor/constructor blocks (not matched
  by srcQL). `detect_system_tainted.sh` additionally implements Stage 2b for the
  ctor/dtor split: `system()` sink in destructor with `fgets`/`getenv` in sibling
  constructor → `error/vulnerability`.

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

## Test Results

**SmellDetect — 12/12 test cases (100%)**

`bad_*` cases are expected to produce at least one finding (any severity).
`good_*` cases are expected to produce zero findings.

| Group           | Bad | Good | TP | TN | FP | FN | Severity |
|-----------------|-----|------|----|----|----|-----|---------|
| system_console  | 1   | 1    | 1  | 1  | 0  | 0  | error/vulnerability |
| system_env      | 1   | 1    | 1  | 1  | 0  | 0  | error/vulnerability |
| popen_console   | 1   | 1    | 1  | 1  | 0  | 0  | error/vulnerability |
| execl_console   | 1   | 1    | 1  | 1  | 0  | 0  | error/vulnerability |
| interprocedural | 1   | 1    | 1  | 1  | 0  | 0  | warning/smell (no taint in 22b) |
| cpp_class       | 1   | 1    | 1  | 1  | 0  | 0  | error/vulnerability (ctor/dtor split) |
| **Total**       | **6** | **6** | **6** | **6** | **0** | **0** | |

### Benchmark comparison (SmellDetect vs cppcheck vs Joern)

| Metric        | SmellDetect | cppcheck | Joern  |
|---------------|-------------|----------|--------|
| Precision     | 100%        | N/A      | TBD    |
| Recall        | 100%        | 0%       | TBD    |
| Avg time      | ~0.30s      | ~0.01s   | TBD    |
| Avg memory    | ~14.8 MB    | ~7.9 MB  | TBD    |

**cppcheck** produces no findings for any CWE-78 test case — it has no dedicated
command injection check in version 2.19.

**Joern** results pending. The CPG-based taint analysis is expected to detect
Groups 1–4 and may detect Group 5 (ctor/dtor) via inter-procedural propagation.

## Known Limitations

- KI-001 (resolved): interprocedural 22b now fires `warning/smell`
- KI-002 (resolved): C++ ctor/dtor split now detected via Stage 2b in `detect_system_tainted.sh`
- `detect_popen_tainted.sh` and `detect_execl_tainted.sh` lack Stage 2b (no cpp_class test cases for those sinks)
- `execvp`, `execve`, `posix_spawn` not covered (KI-007)
- No path sensitivity — co-occurrence model only (KI-006)

See [docs/known_issues.md](docs/known_issues.md) for full details.

## Documentation

- [docs/pipeline.md](docs/pipeline.md) — pipeline architecture and srcML patterns
- [docs/known_issues.md](docs/known_issues.md) — limitations and edge cases
- [docs/variants.md](docs/variants.md) — CWE-78 variant analysis and group breakdown
