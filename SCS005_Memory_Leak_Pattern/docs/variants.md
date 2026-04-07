# SCS005 — Variant Coverage

## Patterns covered by current detectors

| Variant | Detector | Query / Strategy | Status |
|---------|----------|-----------------|--------|
| `malloc` without `free` | `no_free_on_exit` | `CONTAINS malloc($S)` + absent free post-filter | Covered |
| `malloc` with early `return` (no free) | `no_free_on_exit` | Same — no free visible anywhere in function | Covered |
| Pointer overwritten with new `malloc` | `overwrite_leak` | `malloc($A) FOLLOWED BY $PTR = malloc($B)` | Covered |
| `new TYPE()` without `delete` | `new_no_delete` | `CONTAINS new $TYPE()` + absent delete post-filter | Covered |

---

## Extending to additional allocation functions

The `no_free_on_exit` query can be extended to a UNION of allocation calls:

```
FIND $T $FUNC() {} CONTAINS calloc($N, $S)
FIND $T $FUNC() {} CONTAINS realloc($P, $S)
FIND $T $FUNC() {} CONTAINS strdup($STR)
```

Each result is then post-filtered for absent `free()`, using the same Python
post-processor in `detect_no_free_on_exit.sh`.

---

## Variants not covered by current queries

| Variant | Reason | Potential fix |
|---------|--------|---------------|
| `realloc` NULL-return leak (`ptr = realloc(ptr, sz)`) | Requires two-variable data-flow: original ptr vs realloc result | `CONTAINS $P = realloc($P, $S)` query + NULL path analysis |
| Interprocedural: alloc in callee, free in caller | Cross-function; intra-procedural detectors only | `smell_report_multi.sh` + interprocedural srcQL |
| Allocation in loop, single free outside | Structural match sees `free()` present; count mismatch not tracked | Loop-iteration counter analysis (beyond srcQL) |
| `new[]` without `delete[]` (array mismatch) | `delete` present but wrong form | XPath check for `<operator>.delete_array` vs `<operator>.delete` |
| Memory allocated via `mmap` / `VirtualAlloc` | Platform-specific allocation; query must be extended per function name | Union query with platform-specific dealloc (`munmap`, `VirtualFree`) |
| Ownership transferred via return value | Function returns malloc'd pointer to caller | Inter-procedural return-value tracking |
| Exception path leak (C++) | Constructor throws; memory allocated before throw is leaked | C++ exception flow analysis — requires Joern or clang-tidy |

---

## Juliet CWE-401 variant matrix

Juliet generates CWE-401 cases with 22 flow types (01–22). The flow types
most relevant to our detectors:

| Flow | Description | Covered? |
|------|-------------|----------|
| 01 | Baseline — malloc, no free | Yes |
| 06 | Control-flow via `if (STATIC_CONST_TRUE)` | Yes — same structural pattern |
| 07 | Control-flow via `if (data > 5)` | Partial — depends on branch taken |
| 22a/b | Interprocedural (callee allocates) | No — requires multi-file analysis |
| 31 | malloc, copy, no free on copy | Partial — detects original alloc |
| 45 | Allocation stored in global variable | No — global escape not tracked |
