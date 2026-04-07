# SCS008 — Known Issues and Limitations

## False Negatives (Smells Missed)

### KI-001: Interprocedural format string — variable passed across function boundary

**Description:** When the format variable is set in one function and passed to
`printf` in a different function, single-file analysis detects the sink-side
call only if the sink file contains the literal `printf(data)` pattern. If the
sink is wrapped inside a helper function that accepts a `char *fmt` parameter
and calls `printf(fmt)`, the detector flags that helper on every call — which
may or may not be the intended source of the smell.

**Affected group:** `interprocedural` (flows 22a/22b). The detector correctly
targets the sink file (22b) where `printf(data)` appears directly.

**Limitation:** True cross-file dataflow tracking (tracing that `data` in 22b
originated from user input in 22a) is not performed. The detector reports the
structural smell at the sink regardless of the data origin.

---

### KI-002: Compile-time constant variable used as format string

**Description:** If a programmer assigns a fixed string to a variable before
passing it to `printf`, the smell is structurally present but semantically safe:

```c
const char *fmt = "%s\n";
printf(fmt);         // technically a variable, but safe
```

The detector will flag this as a finding because `fmt` is a `<name>` not a
`<literal>`. This is a false positive — the variable is not externally
controlled.

**Impact:** Low in practice. Code that assigns a literal to a `const char *`
and immediately passes it to `printf` is uncommon in security-sensitive paths.

**Mitigation (future):** Track `const char *` initialisers within the same
block; if the variable is initialised to a string literal in the same function
scope and not reassigned, suppress the finding.

---

### KI-003: Wrapper functions around printf not detected

**Description:** A custom logging wrapper such as:

```c
void log_msg(const char *msg) {
    printf(msg);   // detected here
}
log_msg(user_data);   // root cause not detected at call site
```

The detector correctly flags `printf(msg)` inside `log_msg`. However, it does
not trace that `msg` is tainted by `user_data` at the call site. The finding
points to the wrapper body, not the call site — which may cause confusion.

---

## False Positives (Smells Incorrectly Reported)

### KI-004: Variable format strings in legitimate logging code

**Description:** Some logging frameworks intentionally build format strings
programmatically before passing them to `printf`. If the format string is
constructed from trusted, internal sources (not user input), the detector will
still flag it.

**Impact:** Moderate in large codebases with internal logging utilities.

**Mitigation:** Review findings against the data source. If the variable is
populated only from hardcoded strings (not `fgets`, `getenv`, sockets, or
files), the finding can be dismissed.

---

## Tool Limitations

### KI-005: No path sensitivity

The guard-check is structural. If the format argument is any `<name>` node —
regardless of whether that variable was initialised with a literal or with user
input — the smell is reported. There is no data-flow analysis to distinguish
trusted from untrusted format strings within the same function.

### KI-006: `snprintf` and `sprintf` not covered

The current detectors target `printf`, `vprintf`, `fprintf`, `vfprintf`, and
`syslog`. The functions `sprintf(buf, data)` and `snprintf(buf, n, data)` follow
the same pattern (format is arg index 1 for `sprintf`, arg index 2 for
`snprintf`) but are not yet covered by a dedicated detector.

**Workaround:** A fourth detector `detect_sprintf_direct.sh` following the same
pattern as `detect_fprintf_direct.sh` (checking `args[1]` for `sprintf` and
`args[2]` for `snprintf`) can be added without changes to the pipeline.

### KI-007: C++ templates not covered

srcML parses C++ templates, but the detector does not handle template member
function bodies generated from template instantiation. A format-string smell
inside a template function will be detected only if the template definition
itself contains the unguarded call.

### KI-008: cppcheck misses all cases

cppcheck's format-string checks (`invalidPrintfArgType`,
`wrongPrintfScanfArgNum`) require type-mismatch evidence — they flag mismatched
argument types (e.g., passing an `int` where `%s` expects a `char *`), not the
structural absence of a format specifier. Since `printf(data)` with a `char *`
argument is type-correct, cppcheck produces no warning.

Detection would require cppcheck to track whether the format string is a
compile-time constant, which it does not do in default mode.
