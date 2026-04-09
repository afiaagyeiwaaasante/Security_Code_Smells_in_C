# SCS005 — Query / Detection Method Comparison

**Smell:** Memory Leak Pattern
**CWE:** CWE-401 (Missing Release of Memory after Effective Lifetime)
**Patterns covered:** malloc without free, new without delete, overwrite leak, early-return leak

---

## SmellDetect

**Mechanism:** srcML XML annotation + srcQL structural query + Python regex post-filter

Three detectors:

### detect_no_free_on_exit.sh
**srcQL query:**
```
FIND $T $FUNC() {} CONTAINS malloc($SIZE)
```
Finds all functions containing a `malloc()` call. Python post-filter then checks whether the same function block contains a `<name>free</name>` element. If no `free` is found anywhere in the block → finding emitted.

### detect_new_no_delete.sh
**srcQL query:**
```
FIND $T $FUNC() {} CONTAINS new $TYPE()
```
Finds all functions containing a `new` expression. Python checks for the presence of a `delete` operator or keyword in the same block.

### detect_overwrite_leak.sh
**srcQL query:**
```
FIND $T $FUNC() {} CONTAINS malloc($A) FOLLOWED BY malloc($B)
```
Matches functions where `malloc()` is called twice in sequence. Python then checks whether a `free()` call appears between the two allocations; if not, the first allocation is potentially overwritten and leaked.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains any of:
```
memleak | memleakOnRealloc | resourceLeak | autovarInvalidDeallocation
```

**Notes:**
- `memleak` covers heap allocations not freed before function exit.
- `resourceLeak` covers file handles and similar resources.
- `memleakOnRealloc` fires when `realloc()` is called without storing the return value, losing the original pointer.
- Early-return paths are tracked; cppcheck may flag `bad_early_return` cases where SmellDetect does not.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")

val mallocVars = cpg.call.name("malloc", "calloc", "realloc")
  .inAssignment
  .target
  .isIdentifier
  .name
  .toSet

val freedVars = cpg.call.name("free")
  .argument(1)
  .isIdentifier
  .name
  .toSet

val leaked = mallocVars.diff(freedVars)
val detected = leaked.nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Computes set difference: variables assigned from allocation functions minus variables passed to `free()`. Any variable in the difference is considered leaked.

**Known limitation:** Set difference is function-scoped and name-based. Pointers freed via a wrapper function, freed in a called function, or freed under a condition on an early-return path are not tracked — leading to false negatives on `bad_early_return` and `bad_overwrite` patterns.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | srcQL + Python block filter | Flow-sensitive analysis | CPG set difference |
| Patterns covered | no-free, overwrite, new/delete | no-free, early-return | no-free only |
| Early-return detection | No (1 FN) | Yes | No (3 FN) |
| Recall | 75% | 75% | 25% |
| Precision | 100% | 100% | 100% |
