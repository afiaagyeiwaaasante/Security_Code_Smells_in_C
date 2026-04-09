# SCS010 — CWE-259 Variant Analysis

## Juliet Suite Overview

**CWE:** 259 — Use of Hard-coded Password
**Juliet folder:** `CWE259_Hard_Coded_Password`
**Total files:** ~167
**Variants:** `w32_char`, `w32_wchar_t` (Windows-specific sinks only)

## Sources and Sinks (Juliet CWE-259)

| Element | Values |
|---|---|
| Bad source | Hardcoded `#define PASSWORD "ABCD1234!"` copied via `strcpy` |
| Good source | `fgets(password, sizeof(password), stdin)` — runtime input |
| Sink | `LogonUserA(username, domain, password, ...)` — Windows API |
| Variants | `w32_char` (char), `w32_wchar_t` (wide char) |

> **Note:** All Juliet CWE-259 test cases use Windows-specific authentication
> sinks (`LogonUserA`, Win32 API). Our test cases are adapted to cross-platform
> C/C++ using generic `strcmp`-based authentication to support Linux evaluation.

## Flow Variants (S01–S07 numbering)

| Flow | Description | Detectable? |
|---|---|---|
| 01 | Baseline — hardcoded `#define`, `strcpy` into variable | YES — `define_credential` + `password_literal` |
| 02 | Constant from data flow (global int variable) | YES — `define_credential` detects the macro |
| 05–12 | Control-flow variants (if, switch, for, while) | YES — literal in same file |
| 13 | Hardcoded via `GLOBAL_CONST_FIVE` conditional | YES — `define_credential` |
| 22a/b | Interprocedural — literal in 22a, sink in 22b | YES for 22a; FN for 22b only |
| 31–45 | Data copies (memcpy, strcpy variants, pointers) | YES — `define_credential` |
| 51–68 | Multi-function chains (chain a→b, a→b→c etc.) | YES — literal visible in chain root |
| 81–84 | C++ class patterns (heap, stack, global, new/delete) | YES — `password_literal` (strcpy in ctor) |

## Focused Test Groups

### Group 1 — `password_var` (flow 01 basis)
**Smell:** `const char *password = "ABCD1234!";` — credential variable initialised to literal.
**Detector:** `detect_password_literal.sh` — matches `<decl>` with credential name and `<literal type="string">` init that is not inside a `<call>`.
**Good pattern:** `const char *password = getenv("APP_PASSWORD");` — function call, not literal.

### Group 2 — `define_const` (flow 01/13 basis)
**Smell:** `#define PASSWORD "ABCD1234!"` — credential keyword in preprocessor macro with string literal value.
**Detector:** `detect_define_credential.sh` — matches `<cpp:define>` where macro name matches credential keyword and `<cpp:value>` is a quoted string.
**Good pattern:** `#define BUFSIZE 64` — non-credential macro; password from `getenv`.

### Group 3 — `strcmp_auth` (new pattern)
**Smell:** `strcmp(input, "s3cr3t!")` — authentication comparison against a hardcoded literal.
**Detector:** `detect_strcmp_hardcoded.sh` — matches `strcmp`/`strncmp` calls where any argument is a `<literal type="string">`.
**Good pattern:** `strcmp(input, expected)` where `expected` comes from `getenv` — no literal in comparison.

### Group 4 — `interprocedural` (flow 22 basis)
**Smell:** `#define PASSWORD "ABCD1234!"` + `strcpy(g_password, PASSWORD)` in source file 22a. Sink in 22b uses the global without visible literal.
**Detector:** Both `detect_define_credential` and `detect_password_literal` (strcpy pattern) fire on 22a.
**Note:** Running on 22b (sink file only) would be a false negative — the literal is not present there. Running on 22a (where the smell lives) gives correct detection.

### Group 5 — `cpp_class` (flow 84 basis)
**Smell:** `strcpy(password_, "ABCD1234!")` inside a C++ class constructor — hardcoded credential copied to a member variable.
**Detector:** `detect_password_literal.sh` strcpy pattern — first arg has credential name (`password_`), second arg is a string literal.
**Good pattern:** `std::strncpy(password_, env, ...)` where `env` comes from `getenv` — no literal.

## Detection Coverage

| Group | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| password_var | YES | NO | TBD |
| define_const | YES | NO | TBD |
| strcmp_auth | YES | NO | TBD |
| interprocedural | YES (22a) | NO | TBD |
| cpp_class | YES | NO | TBD |

**cppcheck** v2.19 has no `[hardcodedCredentials]` check for these generic cross-platform patterns. It flags `[hardcodedCredentials]` only for specific Windows API calls (e.g., `LogonUserA`) in its library configuration.
