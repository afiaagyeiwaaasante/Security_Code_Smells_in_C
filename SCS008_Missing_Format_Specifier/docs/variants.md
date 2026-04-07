# SCS008 Missing Format Specifier — Variant Analysis (CWE-134)

## CWE Reference
CWE-134: Use of Externally-Controlled Format String

## Smell Description
A variable (whose value derives from user input) is passed directly as the
format string argument to a printf-family function, rather than as a data
argument after a literal format string.  An attacker can inject format
directives (e.g. `%n`, `%x`) to read or write arbitrary memory.

**Bad pattern**  : `printf(data);`
**Good pattern** : `printf("%s\n", data);`

---

## Juliet S01–S06 Breakdown

The Juliet CWE-134 corpus (s01–s06, ~951 files) is organised by:
- **Character type**: `char` (s01–s03) and `wchar_t` (s03–s06)
- **Source** (where user data originates): `connect_socket`, `console`, `environment`, `file`, `listen_socket`
- **Sink** (format function): `fprintf`, `printf`, `snprintf`, `vfprintf`, `vprintf`, `w32_vsnprintf`
- **Flow variant**: 01–18, 21–22, 31–34, 41–45, 51–68, 72–74, 81–84 (same numbering as other CWEs)

---

## 5 Focused Groups (minimal test cases)

### Group 1 — `printf_direct`
- **Source**: console (`fgets` from `stdin`)
- **Sink**: `printf(data)` — variable as first argument
- **Guard (good)**: `printf("%s\n", data)` — literal format string
- **Files**: `bad_printf_direct_01.c`, `good_printf_direct_01.c`

### Group 2 — `fprintf_direct`
- **Source**: file (`fgets` from `FILE *`)
- **Sink**: `fprintf(stderr, data)` — variable as second argument
- **Guard (good)**: `fprintf(stderr, "%s\n", data)`
- **Files**: `bad_fprintf_direct_01.c`, `good_fprintf_direct_01.c`

### Group 3 — `env_format`
- **Source**: `getenv()` — environment variable
- **Sink**: `printf(data)` — env value used directly as format
- **Guard (good)**: `printf("%s\n", data)`
- **Files**: `bad_env_format_01.c`, `good_env_format_01.c`

### Group 4 — `interprocedural` (flow 22)
- **Source**: `fgets` in 22a, stored in shared global buffer
- **Sink**: `printf(data)` in 22b, reading from shared buffer
- **Guard (good)**: `printf("%s\n", data)` in the sink file
- **Files**: `bad_printf_interprocedural_22a.c`, `bad_printf_interprocedural_22b.c`,
            `good_printf_interprocedural_22a.c`, `good_printf_interprocedural_22b.c`
- **Note**: detector targets the sink file (22b); source file has no format call

### Group 5 — `cpp_class` (flow 84)
- **Source**: `fgets` into class member variable in constructor
- **Sink**: `printf(data_)` in destructor — member used as format
- **Guard (good)**: `printf("%s\n", data_)` in destructor
- **Files**: `bad_printf_class_84.cpp`, `good_printf_class_84.cpp`
- **Note**: requires destructor block splitting (`<destructor>` tag in srcML)

---

## Detection Strategy

All three detectors share the same structural check:

1. Split XML into per-function/constructor/destructor blocks.
2. Find a call to the target sink function.
3. Extract the **format argument** (arg 0 for `printf`/`vprintf`; arg 1 for `fprintf`/`vfprintf`/`syslog`).
4. If the format argument contains a `<literal>` element → **guarded** (skip).
5. If the format argument is a `<name>` (variable reference) → **finding**.

| Detector | Sink functions | Format arg index |
|---|---|---|
| `detect_printf_direct.sh` | `printf`, `vprintf` | 0 |
| `detect_fprintf_direct.sh` | `fprintf`, `vfprintf` | 1 |
| `detect_syslog_direct.sh` | `syslog` | 1 |
