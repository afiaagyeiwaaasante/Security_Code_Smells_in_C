# SCS009 — Known Issues and Limitations

## False Negatives (Smells Missed)

### KI-001: Interprocedural command injection — taint source in a different file

**Status: RESOLVED** — detectors now fire `warning/smell` on the sink-side file.

**Description:** When the user input is read in one function (or file) and the
OS command sink is called in a different function (or file), the detector cannot
correlate the two. The sink-side block contains no `fgets`/`getenv` call, so
the co-occurrence guard correctly prevents a false positive — but also misses
the real taint flow.

**Affected group:** `interprocedural` (flows 22a/22b). `bad_system_interprocedural_22a.c`
reads user input into a global; `bad_system_interprocedural_22b.c` calls
`system(badData)` but contains no `fgets`/`getenv`.

**Fix (Stage 1 smell fallback):** When the structural pattern is found
(non-literal command argument) but no taint source is visible in the same
function scope, all three detectors (`detect_system_tainted.sh`,
`detect_popen_tainted.sh`, `detect_execl_tainted.sh`) now emit
`severity=warning, classification=smell` instead of suppressing the finding.
A co-located taint source still escalates to `error/vulnerability`.

**Remaining limitation:** The `22b` finding is `warning/smell` rather than
`error/vulnerability` because taint is not visible in that file alone.
Full cross-file classification requires interprocedural dataflow (e.g., Joern CPG).

---

### KI-002: C++ class — taint source in constructor, sink in destructor

**Status: RESOLVED** — detector now fires `error/vulnerability` via Stage 2b.

**Description:** In a C++ class where the constructor reads user input into a
member variable and the destructor calls `system(data_)`, the constructor body
and destructor body are separate `<constructor>` and `<destructor>` XML blocks.
The co-occurrence guard sees no `fgets`/`getenv` in the destructor block and
skips it.

**Affected group:** `cpp_class` (flow 84). `bad_system_class_84.cpp` exhibits
this pattern.

**Fix (Stage 2b — ctor/dtor split XPath):** A new XPath stage was added to
`detect_system_tainted.sh` that targets this cross-block pattern directly:
```xpath
//*[local-name()='call']
  [*[local-name()='name'][.='system']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [not(.//*[local-name()='literal'])]]
  [ancestor::*[local-name()='destructor']]
  [ancestor::*[local-name()='class'][1]
    [.//*[local-name()='constructor']
      [.//*[local-name()='call']
        [*[local-name()='name'][.='fgets' or .='getenv']]]]]
```
This matches a `system()` with a non-literal argument inside a destructor,
where a sibling constructor (same class) contains a taint source. The finding
is emitted as `error/vulnerability`.

**Remaining limitation:** `detect_popen_tainted.sh` and `detect_execl_tainted.sh`
do not yet have a Stage 2b block; no cpp_class test cases exist for those
sinks so the gap is currently untested.

---

### KI-003: Taint via file or socket sources not covered

**Description:** The detectors recognise `fgets` and `getenv` as taint sources.
Juliet also uses `fscanf`, `fread`, `recv`, `read`, and connect/listen socket
reads as sources. These are not in the `INPUT_SOURCE` pattern.

**Impact:** Smells where the command string is built from socket or file input
(rather than console or environment) are not detected.

**Mitigation:** Extend the taint-source check in the `ancestor::` predicate to include additional sources:
```xpath
[.//*[local-name()='call']
  [*[local-name()='name']
    [.='fgets' or .='getenv' or .='fscanf' or .='fread' or .='recv' or .='read']]]
```

---

## False Positives (Smells Incorrectly Reported)

### KI-004: Const variable used as command string

**Description:** If a programmer assigns a fixed path to a variable before
calling `system`, the smell is structurally present but semantically safe:

```c
const char *cmd = "/usr/bin/ls";
system(cmd);   // flagged — cmd is a <name>, not a <literal>
```

If `fgets` or `getenv` is also present in the same block (for an unrelated
purpose), the detector will emit a false positive.

**Impact:** Low in practice. Rarely does code call `system` with a hardcoded
variable alongside an unrelated `fgets` call.

**Mitigation:** Track `const char *` initialisers; if the variable is set to a
string literal and not reassigned, suppress the finding.

---

### KI-005: Sanitised data still flagged

**Description:** If user input is read with `fgets`, sanitised (e.g., escaping
shell metacharacters), and then passed to `system`, the detector will still
flag it because it cannot verify the sanitisation at the structural level.

```c
fgets(raw, sizeof(raw), stdin);
sanitise(raw, safe);   // user-defined sanitiser
system(safe);           // flagged — safe is a <name>
```

**Impact:** Any code that performs sanitisation in a separate function before
calling the sink will be flagged as long as `fgets`/`getenv` is present in the
same block.

**Mitigation:** This is inherent to the co-occurrence (structural) detection
model. A user-defined sanitiser cannot be distinguished from a pass-through
without a full semantic analysis.

---

## Tool Limitations

### KI-006: No path sensitivity

The guard-check is structural and block-scoped. The detector does not trace
which variable is tainted by `fgets`/`getenv` and whether that specific
variable flows into the `system()` call. It only confirms that both occur
in the same block.

### KI-007: `execvp`, `execve`, `posix_spawn` not covered

The current detectors target `system`, `popen`, `execl`, and `execlp`. The
functions `execvp(path, argv)` and `execve(path, argv, envp)` follow the same
pattern (path is first argument) but are not covered by a dedicated detector.

**Workaround:** A fourth detector following the same pattern as
`detect_execl_tainted.sh` but targeting `execvp` and `execve` can be added
without changes to the pipeline.

### KI-008: cppcheck misses all CWE-78 cases

cppcheck 2.19 does not have a dedicated command injection check. Its
`--enable=all` mode checks for `constVariablePointer` style issues and
`staticFunction` suggestions, but does not flag `system(data)` as a security
risk. No findings are produced for any of the test cases (0/10).

This contrasts with Joern, which can detect the pattern via its CPG-based
taint analysis.

### KI-009: Windows sinks excluded

The Juliet suite includes Windows-specific sinks (`_wsystem`, `ShellExecuteA`,
`WinExec`). These are not covered by the current detectors. The detectors
target POSIX/Linux sinks only: `system`, `popen`, `execl`, `execlp`.
