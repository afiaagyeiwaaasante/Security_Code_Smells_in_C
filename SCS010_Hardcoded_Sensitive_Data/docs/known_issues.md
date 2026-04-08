# SCS010 — Known Issues and Limitations

## False Positives (Smells Incorrectly Reported)

### KI-001: Non-secret string literals in credential-named variables

**Description:** If a credential-named variable is initialised to a string
that is not actually a secret (e.g., a display label or status string), the
detector will flag it:

```c
const char *password_hint = "Enter your password:";  // flagged — name matches
```

**Impact:** Low in practice. Variables named `password` rarely hold non-secret
strings in real code.

**Mitigation:** Review findings in context. The `varname` field in the JSON
finding gives the variable name; verify the literal value is actually a
credential.

---

### KI-002: strcmp with non-password literals

**Description:** The `detect_strcmp_hardcoded` detector flags ALL
`strcmp`/`strncmp` calls with a string literal argument, including comparisons
that are not authentication-related:

```c
if (strcmp(type, "application/json") == 0)  // flagged — literal in strcmp
```

**Impact:** Moderate in large codebases with many string type comparisons.

**Mitigation (future):** Add context filtering — only flag `strcmp` calls inside
functions with authentication-related names (`auth`, `login`, `verify`, `check`)
or where one argument matches a credential keyword name. This would require
function-name context from the `<function><name>` block.

---

### KI-003: Compile-time constant via `const` variable

**Description:** If a password is stored in a `const` variable that is itself
initialised from another `const` or `#define`, the detector may miss the
transitive chain:

```c
const char *MASTER = "secret";   // flagged — MASTER matches no keyword
const char *password = MASTER;   // not flagged — no literal in init
```

The first `const` variable `MASTER` is not flagged (name doesn't match keywords).
The second `password` is not flagged (init contains `<name>`, not `<literal>`).

**Impact:** Low. Transitive literal assignments are uncommon.

---

## False Negatives (Smells Missed)

### KI-004: Interprocedural — literal in source file only

**Description:** When the hardcoded password is set in file 22a and used for
authentication in file 22b, the detector correctly flags 22a. However, if
the analysis is restricted to 22b (the sink file), the detector produces no
finding because no literal is visible in that file.

**Affected group:** `interprocedural` — running on 22b is a known false negative
by design. Scanning the full codebase (both files) gives correct detection.

---

### KI-005: Obfuscated or encoded credentials not detected

**Description:** If a password is obfuscated before storage:

```c
const char *password = "\x41\x42\x43\x44";  // hex-encoded "ABCD"
```

Or stored as integer then converted, the detector will not recognise it as a
hardcoded credential. The `<literal type="string">` check only matches standard
quoted string literals, not character escape sequences or computed values.

---

### KI-006: Wide-character passwords not covered

**Description:** The Juliet suite includes `w32_wchar_t` variants using `wchar_t`
and `wcscpy`/`wcscmp`. The current detectors target `char *` variable
declarations and narrow-character string functions. Wide-character variants are
not covered.

**Workaround:** Extend the `STRCPY_CALL` regex in `detect_password_literal.sh`
to also match `wcscpy`, and add `wcscmp`/`wcsncmp` to `detect_strcmp_hardcoded.sh`.

---

## Tool Limitations

### KI-007: No semantic context for strcmp

The `detect_strcmp_hardcoded` detector does not verify whether the `strcmp` call
is actually used in an authentication context (e.g., inside an `if` condition
guarding access). Any `strcmp` with a literal is flagged. This is intentional —
the structural smell is the presence of the hardcoded literal regardless of
whether it gates access.

### KI-008: cppcheck misses all cross-platform cases

cppcheck v2.19's `[hardcodedCredentials]` check is limited to specific Windows
API calls (e.g., `LogonUserA`, `SQLConnect`). It does not detect generic
patterns such as `char *password = "secret"` or `strcmp(input, "secret")` in
cross-platform code (0/10 in our evaluation).

### KI-009: Macro expansion not tracked

When a `#define PASSWORD "ABCD1234!"` is used in `strcmp(input, PASSWORD)`, the
`detect_strcmp_hardcoded` detector does NOT flag the `strcmp` call — because
`PASSWORD` appears as a `<name>` node (macro identifier) in the XML, not as a
`<literal>` (srcML does not expand macros). The smell is captured instead by
`detect_define_credential` on the `#define` line itself.
