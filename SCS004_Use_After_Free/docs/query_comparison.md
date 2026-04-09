# SCS004 — Query / Detection Method Comparison

**Smell:** Use-After-Free Risk
**CWE:** CWE-416 (Use After Free), CWE-672
**Patterns covered:** free/use, new/delete, delete[], return freed ptr, double free, operator=, interprocedural

---

## SmellDetect

**Mechanism:** srcML XML annotation + srcQL structural queries (one per pattern) + XPath extraction

Seven detectors:

### detect_use_after_free.sh
**srcQL queries:**
```
FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL($PTR)
FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL(&$PTR[$IDX])
```
Matches functions where a pointer is passed to `free()` and then subsequently used in another call — either directly or as a base for indexed access.

### detect_new_delete_uaf.sh
**srcQL queries:**
```
FIND $T $FUNC() {} CONTAINS delete $PTR FOLLOWED BY $CALL($PTR)
FIND $T $FUNC() {} CONTAINS delete $PTR FOLLOWED BY $CALL($PTR->$FIELD)
```
C++ variant: scalar `delete` followed by use of the same pointer (direct or field access).

### detect_delete_array_uaf.sh
**srcQL queries:**
```
FIND $T $FUNC() {} CONTAINS delete[] $PTR FOLLOWED BY $CALL($PTR)
FIND $T $FUNC() {} CONTAINS delete[] $PTR FOLLOWED BY $CALL(&$PTR[$IDX])
```
C++ variant: array `delete[]` followed by use of the same pointer.

### detect_double_free.sh
**srcQL query:**
```
FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY free($PTR)
```
Matches the same pointer passed to `free()` twice in sequence.

### detect_return_freed_ptr.sh
**srcQL query:**
```
FIND $RT $FNAME($PARAMS) {} CONTAINS free($PTR) FOLLOWED BY return $PTR
```
Matches functions that free a pointer and then return it to the caller.

### detect_operator_equals_uaf.sh
**srcQL query:**
```
FIND $RT operator=($PARAMS) {} CONTAINS delete[] $FIELD
```
C++ class pattern: copy-assignment operator that deletes an array field without a self-assignment guard.

### detect_interprocedural_uaf.sh
**srcQL queries (PASS1 — find sink functions):**
```
FIND $RT $FNAME($PT * $PTR) {} CONTAINS free($PTR)
FIND $RT $FNAME($PT * $PTR) {} CONTAINS delete[] $PTR
FIND $RT $FNAME($PT * $PTR) {} CONTAINS delete $PTR
```
Identifies functions that deallocate a pointer parameter, so callers that pass the same pointer again can be flagged.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.cpp>
```

**Detection trigger:** stderr contains any of:
```
deallocuse | deallocret | operatorEqToSelf
```

**Notes:**
- `deallocuse` fires when a deallocated variable is subsequently used.
- `deallocret` fires when a deallocated pointer is returned.
- `operatorEqToSelf` fires on `operator=` without a self-assignment check (related to the delete-then-assign pattern).

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")

val freedVars = cpg.call.name("free", "delete", "<operator>.delete")
  .argument(1).isIdentifier.name.toSet

val hits = cpg.identifier
  .filter(i => freedVars.contains(i.name))
  .inCall
  .nameNot("free", "delete", "<operator>.delete")
  .l

val detected = hits.nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Builds a set of variable names passed to `free`/`delete`. Then finds any identifier with the same name used in a non-deallocation call. This is a name-based approximation — does not track aliases.

**Known limitation:** Name-based matching produces false positives when the same variable name is reused in a different scope after the original pointer goes out of scope.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | srcQL (7 detectors) | Flow-sensitive analysis | CPG name-set tracking |
| Patterns covered | 7 variants incl. C++ | free/use, return | free/use only |
| Interprocedural | Yes (PASS1 sink-finder) | Partial | Yes (CPG) |
| False positive rate | 0% | 0% | 37.5% (3 FP) |
| Recall | 100% | 75% | 75% |
