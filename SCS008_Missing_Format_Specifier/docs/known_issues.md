# SCS008 — Known Issues and Limitations

## False Negatives (Smells Missed)

### KI-001: Interprocedural format string — taint source in a different file

**Description:** When the user input is read in one function (or file) and the
printf sink is called in a different function (or file), the detector cannot
correlate the two. The sink-side block contains no `fgets`/`getenv`/`scanf`
call, so the taint co-occurrence guard correctly prevents a false positive —
but also misses the real taint flow.

**Affected group:** `interprocedural` (flows 22a/22b). `bad_printf_interprocedural_22a.c`
reads user input into a global; `bad_printf_interprocedural_22b.c` calls
`printf(data)` but contains no taint source. The detector produces no finding
on 22b (known false negative).

**Limitation:** Cross-file / cross-function taint tracking requires a full
dataflow graph (e.g., Joern's CPG). The structural analyser is intentionally
single-block scoped.

---

### KI-002: C++ class — taint source in constructor, sink in destructor

**Description:** In a C++ class where the constructor reads user input into a
member variable and the destructor calls `printf(data_)`, the constructor body
and destructor body are separate `<constructor>` and `<destructor>` XML blocks.
The taint co-occurrence guard sees no `fgets`/`getenv`/`scanf` in the destructor
block and suppresses the finding.

**Affected group:** `cpp_class` (flow 84). `bad_printf_class_84.cpp` exhibits
this pattern. The detector produces no finding (known false negative).

**Limitation:** Cross-block (ctor → member → dtor) taint tracking is not
supported. This would require inter-method data-flow analysis.

---

### KI-003: Wrapper functions around printf not detected

**Description:** A custom logging wrapper that accepts a format string and calls
printf internally will not be detected unless the wrapper's body also contains
a taint source:

```c
void log_msg(const char *msg) {
    printf(msg);   // no fgets/getenv in this function → suppressed
}
log_msg(user_data);   // root cause not detected at call site
```

The taint co-occurrence guard suppresses `printf(msg)` inside `log_msg` because
no taint source is visible in the same function.

**Limitation:** This is inherent to the single-block co-occurrence model.
Detecting taint flow through wrapper arguments requires interprocedural analysis.

---

### KI-004: Taint via socket or file sources not covered

**Description:** The detectors recognise `fgets`, `getenv`, `scanf`, and
`fscanf` as taint sources. Sources such as `recv`, `read`, `fread`, and socket
reads are not in the taint source list.

**Impact:** Format string smells where the string is built from socket or file
input are not detected.

**Mitigation:** Extend the taint source check in the `count()` predicate:
```xpath
count(//*[local-name()='call'][*[local-name()='name']
  [.='fgets' or .='getenv' or .='scanf' or .='fscanf'
   or .='recv' or .='read' or .='fread']])
```

---

## False Positives (Smells Incorrectly Reported)

### KI-005: Const variable used as format string alongside unrelated taint source

**Description:** If a programmer assigns a fixed string to a variable before
calling printf, AND an unrelated `fgets`/`getenv` call is present in the same
function (for a different purpose), the detector will emit a false positive:

```c
fgets(input, sizeof(input), stdin);   // unrelated taint source
const char *fmt = "%s\n";
printf(fmt);                           // flagged — fmt is a <name>, not a <literal>
```

**Impact:** Low in practice. Rarely does code use a hardcoded-variable format
string alongside an unrelated fgets call.

**Mitigation:** Track `const char *` initialisers; if the variable is set to a
string literal and not reassigned, suppress the finding.

---

## Tool Limitations

### KI-006: No path sensitivity

The taint co-occurrence check is structural and block-scoped. The detector does
not trace which variable is tainted by the taint source and whether that specific
variable flows into the printf format argument. It only confirms that both a
non-literal format argument and a taint source call occur in the same function.

### KI-007: `snprintf` and `sprintf` not covered

The current detectors target `printf`, `vprintf`, `fprintf`, `vfprintf`, and
`syslog`. The functions `sprintf(buf, data)` and `snprintf(buf, n, data)` follow
the same pattern but are not yet covered by a dedicated detector.

**Workaround:** A fourth detector `detect_sprintf_direct.sh` following the same
srcQL + XPath structure can be added without changes to the pipeline.

### KI-008: cppcheck misses all cases

cppcheck's format-string checks (`invalidPrintfArgType`,
`wrongPrintfScanfArgNum`) require type-mismatch evidence — they flag mismatched
argument types, not the structural absence of a format specifier. Since
`printf(data)` with a `char *` argument is type-correct, cppcheck produces no
warning.
