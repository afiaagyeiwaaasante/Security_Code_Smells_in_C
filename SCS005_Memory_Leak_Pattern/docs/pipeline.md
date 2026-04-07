# SCS005 Pipeline Architecture

## Overview

The SCS005 detector uses the same three-stage srcML pipeline as SCS003/SCS004,
feeding annotated XML into structural detectors that use srcQL queries and
XPath post-filtering.

```
Source file (.c / .cpp)
        │
        ▼ Stage 1 — srcml
   srcML XML  (position + hash attributes)
        │
        ▼ Stage 2 — srcslice
   Slice JSON  (def/use chains, data-flow slices)
        │
        ▼ Stage 3 — srcattributor
   Annotated XML  (slice data merged back into srcML)
        │
        ├──► Detector 1: detect_no_free_on_exit.sh
        ├──► Detector 2: detect_overwrite_leak.sh
        └──► Detector 3: detect_new_no_delete.sh
                │
                ▼
           findings.json  (one JSON object per finding)
                │
                ▼
           report summary (stdout + .txt file)
```

---

## Detector 1 — no_free_on_exit

**Pattern**: `malloc()` called but `free()` never called in the same function.

**srcQL query**:
```
FIND $T $FUNC() {} CONTAINS malloc($SIZE)
```

**Post-filter (XPath / Python)**:
For each function matched by the query, check whether the function body also
contains a `<name>free</name>` call node. If absent → the allocation has no
corresponding deallocation → emit a `warning [memoryLeak]` finding at the
`malloc()` call site.

**Why not a pure srcQL query?**
srcQL does not support a `NOT CONTAINS` clause in its current form. The
post-filter in Python fills this gap by inspecting each matched function block.

---

## Detector 2 — overwrite_leak

**Pattern**: pointer `$PTR` is reassigned a new `malloc()` without first
freeing the original allocation.

**srcQL query**:
```
FIND $T $FUNC() {} CONTAINS $PTR = malloc($A) FOLLOWED BY $PTR = malloc($B)
```

**Post-filter**:
After extracting the two malloc positions, the Python post-processor checks
whether any `free()` call appears between them in the function. If no
intermediate `free()` → the first block is leaked → emit `warning [overwriteLeak]`
at the second (overwrite) malloc site, with a note pointing to the first.

---

## Detector 3 — new_no_delete

**Pattern**: C++ `new TYPE()` allocated but `delete` never called before the
pointer goes out of scope.

**srcQL query**:
```
FIND $T $FUNC() {} CONTAINS new $TYPE()
```

**Post-filter**:
Same strategy as Detector 1: for each matched function, check for the absence
of a `delete` expression. If absent → emit `warning [newNoDelete]` at the
`new` site.

---

## Finding schema

```json
{
  "detector": "no_free_on_exit",
  "severity": "warning",
  "rule":     "memoryLeak",
  "file":     "bad_malloc_no_free_01.c",
  "line":     9,
  "col":      16,
  "varname":  "data",
  "note": {
    "line":    9,
    "col":     16,
    "message": "malloc() in bad_malloc_no_free() — no free() on any exit path"
  }
}
```

| Field | Description |
|---|---|
| `detector` | Detector that produced this finding |
| `severity` | `warning` — smell requiring review |
| `rule` | `memoryLeak` / `overwriteLeak` / `newNoDelete` |
| `file` | Source file path |
| `line` / `col` | Location of the leak site (malloc / overwrite / new) |
| `varname` | Pointer variable involved |
| `note` | Points to the allocation site with an explanatory message |
