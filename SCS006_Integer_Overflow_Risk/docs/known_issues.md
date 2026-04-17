# SCS006 — Known Issues and Limitations

## False Negatives (Smells Missed)

### KI-001: Interprocedural overflow — no cross-file data flow

**Description:** When tainted data originates in a source file (`22a.c` —
contains the `fscanf` call) and the arithmetic operation is performed in a
separate sink file (`22b.c` — receives the value as a parameter), single-file
analysis of `22b.c` alone cannot see the taint source. The detector fires on
`22b.c` because the arithmetic has no MAX guard, but classifies the finding as
`warning/smell` (no taint source visible) rather than `error/vulnerability`.

**Affected files:** `interprocedural/bad_int_multiply_22a.c` + `22b.c`,
`bad_int_add_22a.c` + `22b.c`

**Current handling:** The `22a` (source-only) files are explicitly excluded
from `run_test.sh` and `run_smelldetect.sh`. Only the `22b` (sink) files are
benchmarked; they correctly produce a finding but with downgraded severity.

**Limitation:** `smell_report_multi.sh` does not exist for SCS006. Full
interprocedural taint tracking (correct `error/vulnerability` classification)
would require a multi-file analysis pass that combines both files into one
srcML unit before running the detectors.

---

### KI-002: Guard expressed without named MAX constant

**Description:** A programmer may write the guard as a numeric literal rather
than a symbolic constant, e.g.:

```c
if (data <= 2147483647 / 2) { /* INT_MAX / 2 */ ... }
```

The detector only searches `<condition>` for `INT_MAX`, `CHAR_MAX`, etc., not
for their numeric equivalents. Such guards will be missed, causing the detector
to report a false positive.

**Impact:** Low in practice — well-maintained code uses symbolic names. Numeric
guards could be detected with a separate pattern that checks for comparison
operators immediately before an arithmetic operation, but this increases the
false-positive rate on unrelated comparisons.

---

### KI-003: Overflow check using subtraction (`INT_MAX - data`)

**Description:** Some valid guards are written as:

```c
if (b <= INT_MAX - a) { result = a + b; }
```

This guard contains `INT_MAX` inside `<condition>`, so Detector 2 correctly
suppresses the finding. No issue here — documented for completeness.

---

### KI-004: Squaring via `data * data` — sqrt(MAX) guard not matched

**Description:** The canonical guard for a squaring operation is:

```c
if (llabs(data) <= (long long)sqrt(INT64_MAX)) { result = data * data; }
```

The condition contains neither `INT_MAX` (it uses `INT64_MAX`) nor a simple
comparison — it involves a `sqrt()` call and a cast. Our current guard-check
regex looks for MAX constants by name and will match `INT64_MAX`. Tests confirm
this works for `bad_int64_square_01.c`. However, if the guard uses `sqrt` with
a numeric literal instead of `INT64_MAX`, it will be missed (see KI-002).

---

## False Positives (Smells Incorrectly Reported)

### KI-005: Deliberate wraparound arithmetic (unsigned types)

**Description:** Unsigned integer wraparound is defined behaviour in C/C++ and
is intentionally used in some algorithms (hash functions, checksum loops,
cryptographic primitives). The `detect_unchecked_add.sh` detector will flag any
`+` in a function that has no `UINT_MAX` guard, even when wraparound is
intentional.

**Mitigation:** The smell targets suspicious patterns in security-sensitive
code. Reviewers should assess whether wraparound is intentional or accidental.
A comment like `/* intentional wrap */` does not suppress the finding.

**Workaround (future):** Add an opt-out annotation or whitelist mechanism.

---

### KI-006: Loop increment `i++` flagged as unchecked increment

**Description:** A `for` loop counter increment — `for (int i = 0; i < n; i++)`
— will be flagged by `detect_unchecked_increment.sh` because the `++` is not
guarded by a MAX constant. Standard loop bounds (`i < n`) do not use symbolic
MAX constants.

**Impact:** High false-positive rate for files with many loops.

**Mitigation (current):** The detector is intended for use on files where
overflow risk in data-driven values (not loop counters) is the concern.
A future refinement could check whether the incremented variable is also used
in a comparison with a user-controlled bound.

---

## Tool Limitations

### KI-007: No path sensitivity

The guard-check is structural, not path-sensitive. If a MAX check exists anywhere
in the same function body — even on a dead code path — the detector will suppress
the finding. Conversely, a MAX check in a different `if` branch than the
arithmetic will still suppress the finding even if the check does not logically
guard the operation.

### KI-008: C++ templates not covered

srcML parses C++ templates but the detector does not handle template specialisation
or member function bodies generated from template instantiation. Overflow risk
inside a template function will be detected only if the template definition itself
contains the arithmetic operator without a guard.

### KI-009: srcQL arithmetic pattern limitation

srcQL does not support binary arithmetic patterns like `FIND $T $FUNC() {} CONTAINS $A * $B`
reliably. Detectors 1 and 2 fall back to direct XML scanning (reading `<operator>*</operator>`
and `<operator>+</operator>` directly from the annotated XML file) rather than
using srcQL queries. This is equivalent in precision but bypasses srcQL's variable
binding, which prevents using the LHS variable name for more precise filtering.
