# SCS010 — Hardcoded Sensitive Data (CWE-259)

## Description

**Hardcoded sensitive data** occurs when a password, secret key, or other
credential value is embedded as a string literal directly in the source code —
in a variable initialiser, a preprocessor macro, or an authentication
comparison. An attacker with access to the source code or compiled binary can
trivially extract the credential and bypass authentication.

**CWE:** [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

**Severity:** `warning [SCS010-PASSWD-VAR | SCS010-PASSWD-DEFINE | SCS010-PASSWD-STRCMP]`

## Smell Patterns

**Bad — variable initialised to a string literal:**
```c
const char *password = "ABCD1234!";   // FLAW: literal visible in binary
```

**Bad — preprocessor macro defines credential:**
```c
#define PASSWORD "ABCD1234!"          // FLAW: literal in macro definition
strcpy(buf, PASSWORD);
```

**Bad — hardcoded string in authentication comparison:**
```c
if (strcmp(input, "s3cr3t!") == 0)   // FLAW: literal visible in binary
```

**Good — credential read from runtime source:**
```c
const char *password = getenv("APP_PASSWORD");   // FIX: not in source
if (strcmp(input, password) == 0)                // FIX: no literal in cmp
```

## Folder Structure

```
SCS010_Hardcoded_Sensitive_Data/
├── src/
│   ├── pipeline.sh                          # Stage 1–3: srcml → srcslice → srcattributor
│   ├── smell_report.sh                      # Orchestrator: pipeline + all detectors
│   ├── report.sh                            # Human-readable report formatter
│   ├── detectors/
│   │   ├── detect_password_literal.sh       # var init + strcpy into credential var
│   │   ├── detect_define_credential.sh      # #define macro with credential name
│   │   └── detect_strcmp_hardcoded.sh       # strcmp/strncmp with literal argument
│   └── lib/
│       └── write_finding.sh                 # Shared JSON finding writer
├── testsuites/
│   └── CWE259/
│       ├── password_var/                    # Group 1 — char *password = "literal"
│       ├── define_const/                    # Group 2 — #define PASSWORD "literal"
│       ├── strcmp_auth/                     # Group 3 — strcmp(input, "literal")
│       ├── interprocedural/                 # Group 4 — flow 22 two-file pattern
│       └── cpp_class/                       # Group 5 — flow 84 C++ class constructor
├── cppcheck/
│   ├── scripts/run_cppcheck.sh
│   └── results/
├── joern/
│   ├── scripts/run_joern.sh
│   └── results/
├── evaluation/
│   ├── run_our_tool.sh
│   ├── compare_report.sh
│   └── comparison_report.txt
├── docs/
│   ├── pipeline.md
│   ├── known_issues.md
│   └── variants.md
└── README.md
```

## Detectors

| Detector | Pattern | Rule |
|---|---|---|
| `detect_password_literal.sh` | `char *password = "literal"` OR `strcpy(password_var, "literal")` | `SCS010-PASSWD-VAR` |
| `detect_define_credential.sh` | `#define PASSWORD "literal"` | `SCS010-PASSWD-DEFINE` |
| `detect_strcmp_hardcoded.sh` | `strcmp(var, "literal")` or `strcmp("literal", var)` | `SCS010-PASSWD-STRCMP` |

All detectors work at the structural level — they check whether a credential
keyword appears alongside a string literal in the appropriate syntactic position,
without requiring dataflow tracking.

## Usage

### Single file

```bash
bash src/smell_report.sh testsuites/CWE259/password_var/bad_password_var_01.c
```

### Comparison benchmarks

```bash
bash evaluation/run_our_tool.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

## Evaluation Results

| | Our Tool | cppcheck | Joern |
|---|---|---|---|
| True Positives (TP) | 5 | 0 | TBD |
| True Negatives (TN) | 5 | 5 | TBD |
| False Positives (FP) | 0 | 0 | TBD |
| False Negatives (FN) | 0 | 5 | TBD |
| Precision | 100% | N/A | TBD |
| Recall | 100% | 0% | TBD |
| Avg wall time | ~0.30s | ~0.01s | TBD |
| Avg peak RSS | ~15.0 MB | ~8.0 MB | TBD |

**Our tool** achieves 100% precision and 100% recall across all five test groups.
The three complementary detectors cover the main structural forms of the smell:
variable initialiser, preprocessor macro, and authentication comparison.

**cppcheck** v2.19 does not flag any of the cross-platform test cases. Its
`[hardcodedCredentials]` check is limited to specific Windows API calls (e.g.,
`LogonUserA`) and does not detect generic `strcmp`-based authentication or
plain variable initialisers.

## Documentation

- [docs/pipeline.md](docs/pipeline.md) — pipeline architecture and srcML patterns
- [docs/known_issues.md](docs/known_issues.md) — limitations and edge cases
- [docs/variants.md](docs/variants.md) — CWE-259 variant analysis and group breakdown
