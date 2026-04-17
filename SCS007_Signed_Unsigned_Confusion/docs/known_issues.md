# SCS007 — Known Issues and Limitations

## False Negatives (Smells Missed)

### KI-001: Interprocedural — signed value originates in a separate file

**Description:** When the tainted signed integer is read in a source file
(`22a.c` — contains the `fscanf` call) and passed to `malloc()` in a separate
sink file (`22b.c` — receives the value as a parameter), single-file analysis
of `22b.c` alone cannot see the taint source. The detector fires on `22b.c`
because the signed variable has no positivity guard, but classifies the finding
as `warning/smell` (no taint source visible) rather than `error/vulnerability`.

**Affected group:** `interprocedural/bad_signed_malloc_22a.c` + `22b.c`

**Current handling:** The `22a` (source-only) files are explicitly excluded
from `run_test.sh` and `run_smelldetect.sh`. Only the `22b` (sink) files are
benchmarked; they correctly produce a finding but with downgraded severity.

**Limitation:** `smell_report_multi.sh` does not exist for SCS007. Full
interprocedural taint tracking (correct `error/vulnerability` classification)
would require a multi-file analysis pass that combines both files into one
srcML unit before running the detectors.

---

### KI-002: Guard in constructor, sink in destructor (C++ class flows 83–84)

**Description:** Juliet flows 83 and 84 store the signed value in the
constructor and consume it in the destructor. The detector processes each
XML block (`<constructor>`, `<destructor>`) independently. If the guard
(`data > 0`) appears only in the constructor but `malloc(storedData)` is
in the destructor, the destructor block contains no `&gt;` condition and
the good case would be falsely flagged.

**In practice:** The Juliet good patterns include the guard in the
destructor body (not only the constructor), so evaluation results are
unaffected. This remains a known limitation for real-world C++ code where
validation and use are split across constructor/destructor.

---

### KI-003: `calloc()` not covered

**Description:** `calloc(n, size)` takes a count argument `n` that is also
subject to signed-to-unsigned conversion. The three detectors only match
`malloc`, `memcpy`/`memmove`, and `strncpy`. A call like `calloc(data, sizeof(T))`
with a negative `data` is not detected.

**Workaround (future):** Add a `detect_signed_calloc.sh` detector mirroring
`detect_signed_malloc.sh` with a `calloc` sink pattern.

---

## False Positives (Smells Incorrectly Reported)

### KI-004: `malloc(sizeof(...))` — constant size argument

**Description:** A call like `malloc(sizeof(MyStruct))` uses `sizeof()`,
which always returns a positive `size_t` value. No positivity guard is
needed. If the function containing this call has no `&gt;` condition
(no `if` at all), the detector flags it unnecessarily.

**Impact:** Low — `malloc(sizeof(...))` without any `if` in the function
is common in simple allocation wrappers.

**Mitigation:** Review findings where the `varname` field names an
allocation helper function with no data-driven size argument.

---

### KI-005: Guard on a different variable

**Description:** A function may guard one signed value (`if (n > 0)`) but
pass a different unguarded signed variable to `malloc(m)`. The detector
sees `&gt;` in a `<condition>` and suppresses the finding, even though
the guard does not protect the actual sink argument.

**Impact:** Low in most code bases. The detector is conservative — it
prefers false negatives over false positives when any lower-bound check
is present in the function.

---

## Tool Limitations

### KI-006: No path sensitivity

The guard check is structural, not path-sensitive. A `data > 0` check
anywhere in the function body — even on a dead branch — will suppress
the finding for all `malloc(data)` calls in that function, regardless of
whether the check actually guards the specific call site.

### KI-007: No argument-position check

The detector confirms that a `malloc`/`memcpy`/`strncpy` call is present
in a block without a positivity guard, but it does not verify that the
unguarded signed variable is actually the size argument specifically. If
the signed variable is only used as an unrelated argument (e.g., a pointer
arithmetic expression) and the size argument is a safe literal, the
detector may still flag the call.

### KI-008: C++ templates not covered

srcML parses C++ template definitions, but the detector does not handle
template instantiations separately. A signed-size call inside a template
function body is detected from the template definition, not from each
instantiation — meaning one finding covers all instantiations.
