# SCS004 Pipeline Architecture

## Overview

The SCS004 pipeline is identical in structure to SCS003. Three stages of
analysis produce an annotated XML file, which is then queried by each
detector using srcQL.

```
source.c
  │
  ▼ Stage 1: srcml
srcML XML (structural AST)
  │
  ▼ Stage 2: srcslice
srcslice JSON (data-flow slices)
  │
  ▼ Stage 3: srcattributor
annotated XML (AST + slice data merged)
  │
  ├─▶ detect_use_after_free.sh
  ├─▶ detect_double_free.sh
  └─▶ detect_interprocedural_uaf.sh
        │
        ▼
findings JSON  ──▶  report.sh  ──▶  stdout + report file
```

---

## Entry points

| Script | Use case |
|---|---|
| `src/smell_report.sh <file.c>` | Single source file |
| `src/smell_report_multi.sh <a.c> <b.c> [...]` | Cross-file interprocedural analysis |

---

## Stage 1 — srcml

Converts C source to srcML XML. The `--position` flag embeds line/column
numbers; `--hash` adds content hashes for srcattributor.

```bash
srcml "$SRC" --position --hash -o "$XML"
```

---

## Stage 2 — srcslice

Computes data-flow slices on the srcML XML. Each variable that is defined
and used in the program gets a slice entry in the output JSON.

```bash
srcslice -i "$XML" -o "$JSON"
```

---

## Stage 3 — srcattributor

Merges the srcslice JSON back into the srcML XML, adding `slice:def` and
`slice:use` attributes on each relevant AST node. Detectors use these
attributes in srcQL queries to correlate definitions (malloc, free) with
uses.

```bash
srcattributor -i "$JSON" -o "$XML"
```

---

## Detectors

### Detector 1 — use_after_free (`detect_use_after_free.sh`)

**Pattern:** A pointer is freed with `free()` and then used (dereferenced
or indexed) in the same function without being reassigned.

**srcQL query (sketch):**
```
FIND $T $FUNC() {
} CONTAINS free($PTR) FOLLOWED BY $PTR
```

**Severity:** error
**Rule:** `useAfterFree`

Position is reported at the use site. The `free()` call line is captured
as a note.

---

### Detector 2 — double_free (`detect_double_free.sh`)

**Pattern:** `free()` is called twice on the same pointer within a function
without an intervening reassignment or NULL assignment.

**srcQL query (sketch):**
```
FIND $T $FUNC() {
} CONTAINS free($PTR) FOLLOWED BY free($PTR)
```

**Severity:** error
**Rule:** `doubleFree`

Position is reported at the second `free()` call. The first `free()` line
is captured as a note.

---

### Detector 3 — interprocedural_uaf (`detect_interprocedural_uaf.sh`)

**Pattern (two-pass):**

Pass 1 — identify callees that free a parameter without returning a
replacement pointer. These are "unsafe callees".

Pass 2 — identify callers that pass a pointer to an unsafe callee and
then use the pointer after the call.

**Severity:**
- Callee frees parameter: warning / `useAfterFree`
- Caller uses pointer after unsafe call: error / `useAfterFree`

---

## Output format

Each finding is a JSON object written by `lib/write_finding.sh`:

```json
{
  "detector": "use_after_free",
  "severity": "error",
  "rule": "useAfterFree",
  "file": "bad_use_after_free_01.c",
  "line": 12,
  "col": 5,
  "varname": "data",
  "note": {
    "line": 9,
    "col": 5,
    "message": "Memory freed here"
  }
}
```

Multiple findings are written as a sequence of JSON objects (not a JSON
array). The summary script reads them with a depth-counting parser.

---

## srcML namespace prefixes

| Prefix | URI | Used for |
|---|---|---|
| `src` | `http://www.srcML.org/srcML/src` | All structural AST nodes |
| `pos` | `http://www.srcML.org/srcML/position` | Line/column attributes |
| `slice` | `http://www.srcML.org/srcML/slice` | Data-flow slice annotations |
