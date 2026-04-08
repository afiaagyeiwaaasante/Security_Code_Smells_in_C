# SCS009 Command Injection Risk — Variant Analysis (CWE-78)

## CWE Reference
CWE-78: Improper Neutralization of Special Elements used in an OS Command
(OS Command Injection)

## Smell Description
User-controlled input is incorporated into a string that is passed to an
OS command execution function (`system()`, `popen()`, `execl()`, `execlp()`)
without any sanitisation or validation. An attacker can append shell
metacharacters (`;`, `&&`, `|`, `` ` ``) to inject arbitrary commands.

**Bad pattern** — user input flows into command sink:
```c
char data[100] = "ls ";
fgets(data + 3, sizeof(data) - 3, stdin);  /* user appends to command */
system(data);                               /* FLAW: injected command */
```

**Good pattern (goodG2B)** — only hardcoded data flows into sink:
```c
char data[100] = "ls ";
strcat(data, "*.*");    /* FIX: fixed string, no user input */
system(data);           /* safe: command fully controlled */
```

---

## Juliet S01–S07 Breakdown

The Juliet CWE-78 corpus (s01–s07, ~6,917 files) is organised by:

### Character type
- `char` — s01–s04 (Linux + Windows)
- `wchar_t` — s05–s07 (wide character, Windows-focused)

### Sources (where user data enters)
| Source | Description |
|---|---|
| `console` | `fgets()` reading from `stdin` |
| `environment` | `getenv()` reading an environment variable |
| `connect_socket` | TCP client socket — `recv()` |
| `listen_socket` | TCP server socket — `accept()` + `recv()` |
| `file` | `fgets()` reading from a `FILE *` |

### Sinks (OS command execution functions)
| Sink | Description | Shell? |
|---|---|---|
| `system` | `system(data)` — shell executes entire string | Yes |
| `popen` | `popen(data, "r"/"w")` — pipe to shell command | Yes |
| `execl` | `execl(path, path, arg1, arg3, NULL)` — direct exec | No |
| `execlp` | `execlp(path, path, arg1, arg3, NULL)` — exec via PATH | No |
| `w32_*` | Windows-specific (`_execv`, `_spawnlp`, etc.) | — |

> **Detection focus**: `system` and `popen` are highest-risk (shell interpretation).
> `execl`/`execlp` use fixed paths and are lower risk for injection.
> `w32_*` functions are Windows-only and excluded from our Linux-targeted detector.

### Flow variants (same numbering scheme as CWE-134, CWE-195, etc.)
| Range | Description |
|---|---|
| 01 | Baseline — source and sink in same function |
| 02–18 | Conditional flow variants (if/switch, global flags) |
| 21–22 | Interprocedural — 22a orchestrates, 22b is the source helper |
| 31–34 | Copy via local variable, malloc, struct, typedef |
| 41–45 | Static/global function, nested function, setjmp |
| 51–68 | Multi-level call chains (51a/b, 52a/b/c, …, 67a/b, 68a/b) |
| 72–74 | Array/vector/list containers |
| 81–84 | C++ class patterns — virtual (81/82), stack ctor/dtor (83), heap ctor/dtor (84) |

---

## 5 Focused Groups (minimal test cases)

### Group 1 — `system_console`
- **Source**: console — `fgets()` from `stdin`
- **Sink**: `system(data)`
- **Bad**: `fgets` appends user input to command buffer → `system(data)`
- **Good (goodG2B)**: `strcat(data, "*.*")` hardcoded → `system(data)` — no user input
- **Basis**: s02 `char_console_system` flow 01
- **Detectable**: Yes — `fgets` + `system` co-occur in same block

### Group 2 — `system_env`
- **Source**: environment — `getenv("ADD")`
- **Sink**: `system(data)`
- **Bad**: `getenv()` result appended to command buffer → `system(data)`
- **Good**: fixed string used instead of env var
- **Basis**: s02 `char_environment_system` flow 01
- **Detectable**: Yes — `getenv` + `system` co-occur in same block

### Group 3 — `popen_console`
- **Source**: console — `fgets()` from `stdin`
- **Sink**: `popen(data, "r")`
- **Bad**: user input in command string → `popen(data, "r")`
- **Good**: fixed string → `popen(data, "r")`
- **Basis**: s02 `char_console_popen` flow 01
- **Detectable**: Yes — `fgets` + `popen` co-occur in same block

### Group 4 — `interprocedural` (flow 22)
- **Source**: `fgets()` in `22b` source helper function
- **Sink**: `system(data)` in `22a` orchestrator — calls source, then runs command
- **Bad**: 22a calls badSource() (22b fills buffer via fgets), then system(data)
- **Good**: 22a calls goodSource() (22b uses strcat), then system(data)
- **Basis**: s02 `char_console_system` flow 22a/22b
- **Detectable**: Partial — 22b (source file) has `fgets` but no `system`; 22a has `system` but no `fgets`. Single-file detector cannot see cross-function taint. **Known limitation (KI-001).**

### Group 5 — `cpp_class` (flow 84)
- **Source**: `fgets()` in class constructor — stores tainted data in member
- **Sink**: `system(data_)` in class destructor — executes member as command
- **Bad**: ctor reads stdin → dtor runs system(data_)
- **Good**: ctor uses hardcoded string → dtor runs system(data_)
- **Basis**: s02 `char_console_system` flow 84_bad / 84_goodG2B
- **Detectable**: Partial — ctor and dtor are separate XML blocks. Single-block detector cannot link ctor source to dtor sink. **Known limitation (KI-002).**

---

## Detection Strategy

All three detectors use **same-block co-occurrence**:

1. Split XML into per-function/constructor/destructor blocks.
2. Find blocks that contain a **sink call** (`system`, `popen`, or `execl`/`execlp`).
3. Check whether the **same block** also contains an **input source call** (`fgets` or `getenv`).
4. If both are present → **finding** (tainted input flows into OS command).
5. If sink without source (goodG2B pattern) → **no finding**.

| Detector | Sink functions | Source functions |
|---|---|---|
| `detect_system_tainted.sh` | `system` | `fgets`, `getenv` |
| `detect_popen_tainted.sh` | `popen` | `fgets`, `getenv` |
| `detect_execl_tainted.sh` | `execl`, `execlp` | `fgets`, `getenv` |

### Why co-occurrence works for groups 1–3

In flow-01 (baseline), Juliet places source and sink in the same function body.
The good variant (goodG2B) replaces the source with a `strcat()` of a fixed string —
removing the `fgets`/`getenv` call entirely. The co-occurrence check correctly
distinguishes bad from goodG2B without needing data-flow analysis.
