# SCS010 — Hardcoded Sensitive Data (CWE-259)

## Description

**Hardcoded sensitive data** occurs when a password, secret key, or other
credential value is embedded as a string literal directly in the source code —
in a variable initialiser, a preprocessor macro, or an authentication
comparison. An attacker with access to the source code or compiled binary can
trivially extract the credential and bypass authentication.

**CWE:** [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

**Severity:** `warning [SCS010-PASSWD-VAR | SCS010-PASSWD-DEFINE | SCS010-PASSWD-STRCMP]`

## Vulnerability vs. Smell Classification

SCS010 findings are always classified as `error/vulnerability`. Unlike SCS006–SCS009,
there is no smell variant: a hardcoded credential is exploitable as written regardless
of runtime conditions.

| Condition                  | Severity  | Classification  |
|----------------------------|-----------|-----------------|
| Hardcoded credential found | `error`   | `vulnerability` |

**Why hardcoded credentials are always vulnerabilities:** The secret is readable from
the binary via `strings`, source code review, or disassembly. Hardcoded passwords in
`strcmp` comparisons are bypassable by anyone who can inspect the binary. There is no
runtime condition that prevents exposure. Maps to CWE-259 / CWE-798. `cppcheck`
does not flag this pattern; it is a key differentiator for SmellDetect.

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
│       ├── interprocedural/                 # Group 4 — flow 22 (literal in 22a; 22b has no literal)
│       └── cpp_class/                       # Group 5 — flow 84 C++ class constructor
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
bash evaluation/run_smelldetect.sh
bash cppcheck/scripts/run_cppcheck.sh
bash joern/scripts/run_joern.sh
bash evaluation/compare_report.sh
```

## Test Results

**SmellDetect — 9/9 test cases (100%)**

`bad_*` cases are expected to produce at least one `error/vulnerability` finding.
`good_*` cases are expected to produce zero findings.

| Group           | Bad | Good | TP | TN | FP | FN | Note |
|-----------------|-----|------|----|----|----|-----|------|
| password_var    | 1   | 1    | 1  | 1  | 0  | 0  | |
| define_const    | 1   | 1    | 1  | 1  | 0  | 0  | |
| strcmp_auth     | 1   | 1    | 1  | 1  | 0  | 0  | |
| interprocedural | 1   | —    | 1  | —  | 0  | 0  | 22a tested (literal there); 22b has no literal |
| cpp_class       | 1   | 1    | 1  | 1  | 0  | 0  | |
| **Total**       | **5** | **4** | **5** | **4** | **0** | **0** | |

### Benchmark comparison (SmellDetect vs cppcheck vs Joern)

| Metric        | SmellDetect | cppcheck | Joern  |
|---------------|-------------|----------|--------|
| Precision     | 100%        | N/A      | TBD    |
| Recall        | 100%        | 0%       | TBD    |
| Avg time      | ~0.30s      | ~0.01s   | TBD    |
| Avg memory    | ~15.0 MB    | ~8.0 MB  | TBD    |

**SmellDetect** achieves 100% precision and 100% recall across all test groups.
The three complementary detectors cover the main structural forms: variable
initialiser, preprocessor macro, and authentication comparison.

**cppcheck** v2.19 does not flag any of the cross-platform test cases. Its
`[hardcodedCredentials]` check is limited to specific Windows API calls (e.g.,
`LogonUserA`) and does not detect generic `strcmp`-based authentication or
plain variable initialisers.

## Known Limitations

- Interprocedural 22b (sink file): `strcmp(input, g_password)` with no literal in 22b — known FN by design; literal is in 22a
- Non-secret string literals in credential-named variables may produce FPs (KI-001)
- `const` variable holding a non-password literal alongside credential keyword may FP (KI-003)

See [docs/known_issues.md](docs/known_issues.md) for full details.

## Documentation

- [docs/pipeline.md](docs/pipeline.md) — pipeline architecture and srcML patterns
- [docs/known_issues.md](docs/known_issues.md) — limitations and edge cases
- [docs/variants.md](docs/variants.md) — CWE-259 variant analysis and group breakdown
