# Detection pipeline

## Overview

```
source.c
   │
   ▼
Stage 1 — srcml                →  source.c.xml   (srcML annotated AST)
   │
   ▼
Stage 2 — srcslice             →  source.json    (data-flow slice data)
   │
   ▼
Stage 3 — srcattributor        →  source.c.xml   (slice attrs merged into XML)
   │
   ▼
Stage 4 — detectors (×6)       →  findings.json  (one JSON object per finding)
   │
   ▼
smell_report.sh                →  results/<category>/<base>_report_<ts>.txt
                                   results/<category>/<base>_findings_<ts>.json
```

## Entry point

```bash
bash src/smell_report.sh <source.c> [output_dir]
```

Output is written to `results/<category>/` by default, where `<category>` is
derived from the source file's parent directory name (e.g. `binary_if`, `char`).
An explicit output directory can be passed as the optional second argument.

For multi-file analysis (cross-file interprocedural):

```bash
bash src/smell_report_multi.sh <file_a.c> <file_b.c> [...]
```

---

## Stage 1 — srcml

Converts C source into srcML XML. Both `--position` and `--hash` are
required by downstream tools:

- `--position` adds `pos:start="line:col"` to every node
- `--hash` embeds a file hash that srcattributor uses to locate the
  correct srcML unit when merging slice data

```bash
srcml source.c -l C --position --hash -o source.c.xml
```

---

## Stage 2 — srcslice

Performs data-flow slice analysis. Reads the srcML file and produces
a JSON file where each key is a variable identifier of the form
`varname-line-col-hash`. The `file` field inside each entry records
the path to the original source, which srcattributor uses in stage 3.

```bash
srcslice -i source.c.xml -o source.json
```

**Important:** srcslice records the path to `source.c.xml` inside
the JSON. srcattributor must be run from the same working directory,
and `source.c.xml` must remain at the same path.

---

## Stage 3 — srcattributor

Merges slice data back into the srcML XML as `slice:decl` and
`slice:use` attributes. The `-o` output file must be the same filename
as the srcML from stage 1.

```bash
srcattributor -i source.json -o source.c.xml
```

The `slice:decl` / `slice:use` attributes share a SHA1 hash that
links a variable's declaration site to every use site. This allows
detectors to trace from a dereference back to the original NULL
assignment.

---

## Stage 4 — Detectors

Six shell-based detectors run in sequence against the annotated XML.
Each appends JSON finding objects to a shared temp file. All use
`srcml --srcql` for structural queries and `xmllint --xpath` for
position extraction.

### Detector 1 — binary_if (`detect_binary_if.sh`)

| | |
|---|---|
| **Severity** | error |
| **Rule** | nullPointer |
| **Pattern** | `if((ptr != NULL) & (ptr->field == val))` |
| **Query** | `FIND if(($PTR != NULL) & ($PTR->$FIELD == $VAL)) {}` |

Detects use of bitwise `&` instead of logical `&&` in a null-check
condition. `&` does not short-circuit — both sides are always evaluated,
so `ptr->field` is read even when `ptr` is NULL.

---

### Detector 2 — interprocedural (`detect_interprocedural.sh`)

| | |
|---|---|
| **Severity** | error / warning |
| **Rule** | nullPointer / missingNullCheck |
| **Pattern** | callee dereferences pointer param; caller passes NULL or unguarded ptr |

Two-pass analysis:
- **Pass 1** — finds unsafe callees: functions that dereference a parameter
  without a null guard (candidate sinks)
- **Pass 2** — classifies callers: `error` if the caller explicitly passes
  NULL; `warning` if the caller passes an unguarded pointer

---

### Detector 3 — null_deref (`detect_null_deref.sh`)

| | |
|---|---|
| **Severity** | error |
| **Rule** | nullPointer |
| **Pattern** | `ptr = NULL; ptr->field` or `ptr = NULL; ptr[idx]` |
| **Query (struct)** | `FIND $T $FUNC() {} CONTAINS $TYPE * $PTR = NULL FOLLOWED BY $PTR->$FIELD WHERE NOT (if($PTR != NULL) {})` |
| **Query (array)** | `FIND $T $FUNC() {} CONTAINS $TYPE $PTR = NULL FOLLOWED BY $PTR[$IDX] WHERE NOT (if($PTR != NULL) {})` |

Detects a pointer provably assigned NULL locally then dereferenced with
no null guard anywhere in the function. Covers both struct member (`->`)
and array index (`[]`) dereference patterns.

---

### Detector 4 — missing_guard (`detect_missing_guard.sh`)

| | |
|---|---|
| **Severity** | warning |
| **Rule** | missingNullCheck |
| **Pattern** | `ptr->field` or `ptr[idx]` with no null check in the function |

Detects unguarded dereferences where the pointer is not provably NULL
but has no null check anywhere in the function. Structurally fragile —
any future change to the pointer's source that introduces NULL will
cause a crash.

---

### Detector 5 — deref_after_check (`detect_deref_after_check.sh`)

| | |
|---|---|
| **Severity** | error |
| **Rule** | nullPointer |
| **Pattern** | `if(ptr == NULL) { *ptr }` |
| **Query** | `FIND if($PTR == NULL) {} CONTAINS *$PTR` |

Detects a pointer dereferenced inside the body of `if(ptr == NULL)`.
The condition explicitly confirms the pointer is NULL and the dereference
inside is a guaranteed crash.

---

### Detector 6 — check_after_deref (`detect_check_after_deref.sh`)

| | |
|---|---|
| **Severity** | warning |
| **Rule** | missingNullCheck |
| **Pattern** | `*ptr ... if(ptr != NULL) {}` |
| **Query** | `FIND $T $FUNC() {} CONTAINS *$PTR FOLLOWED BY if($PTR != NULL) {}` |

Detects a null check placed after the pointer has already been
dereferenced. If the pointer is NULL the dereference crashes before
the guard is ever reached — the check is misplaced and gives false
confidence.

---

## Output format

Each detector appends one JSON object per finding to the shared findings
file. The objects are concatenated (not in a JSON array). `smell_report.sh`
copies the temp file to `results/<category>/` at the end.

```json
{
  "detector": "binary_if",
  "severity": "error",
  "rule": "nullPointer",
  "file": "bad_binary_if_01.c",
  "line": 22,
  "col": 29,
  "varname": "ptr",
  "note": {
    "line": 19,
    "col": 5,
    "message": "Assignment 'ptr=NULL', assigned value is 0"
  }
}
```

---

## Namespace reference

| Prefix | URI | Purpose |
|---|---|---|
| `src` | `http://www.srcML.org/srcML/src` | structural elements |
| `pos` | `http://www.srcML.org/srcML/position` | line/col positions |
| `slice` | `http://www.srcML.org/srcML/slice` | data-flow attributes |
| `cpp` | `http://www.srcML.org/srcML/cpp` | preprocessor directives |
