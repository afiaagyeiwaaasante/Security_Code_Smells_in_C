# SCS003 — Query / Detection Method Comparison

**Smell:** Missing NULL Check
**CWE:** CWE-476 (NULL Pointer Dereference), CWE-690
**Patterns covered:** binary-if null test, deref before check, check after deref, missing guard, interprocedural

---

## SmellDetect

**Mechanism:** srcML XML annotation + srcQL structural queries (one per pattern) + XPath extraction

Six detectors, each targeting a distinct variant:

### detect_binary_if.sh
**srcQL query:**
```
FIND if(($PTR != NULL) & ($PTR->$FIELD == $VAL)) {}
```
Targets the anti-pattern where both the null check and a field access appear in the same `if` condition using bitwise `&`, meaning the dereference evaluates even when `$PTR` is NULL.

### detect_check_after_deref.sh
**srcQL query:**
```
FIND $T $FUNC() {} CONTAINS *$PTR FOLLOWED BY if($PTR != NULL) {}
```
Matches functions where a pointer is dereferenced, then checked for NULL afterward — the check is too late.

### detect_deref_after_check.sh
**srcQL query:**
```
FIND if($PTR == NULL) {} CONTAINS *$PTR
```
Matches an `if($PTR == NULL)` block that itself dereferences `$PTR` inside its body — dereference on the null branch.

### detect_interprocedural.sh
**srcQL query (PASS1):**
```
FIND $RT $FNAME($PT * $PTR) {} CONTAINS $PTR->$FIELD
  WHERE NOT (if($PTR != NULL) {})
  UNION
FIND $RT $FNAME($PT * $PTR) {} CONTAINS $PTR[$IDX]
  WHERE NOT (if($PTR != NULL) {})
  DIFFERENCE
FIND $RT $FNAME($PT * $PTR) {} CONTAINS if($PTR != NULL) {}
```
Finds sink functions that accept a pointer parameter and dereference it without a local null guard — the caller is responsible for the check.

### detect_missing_guard.sh / detect_null_deref.sh
Parameterised helpers: accept a query string and run it via `srcml --srcql`, extract XPath positions, emit findings.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains any of:
```
nullPointer | nullPointerOutOfMemory | bitwiseOnBoolean | uninitvar
```

**Notes:**
- `nullPointer` covers straightforward dereferences of possibly-null pointers.
- `bitwiseOnBoolean` covers the binary-if pattern where `&` is used instead of `&&`.
- `nullPointerOutOfMemory` covers `malloc()` return values used without a null check.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")

// Pattern 1: variable assigned NULL (literal 0), then dereferenced
val nullPtrs = cpg.assignment
  .where(_.source.isLiteral.codeExact("0"))
  .target.isIdentifier.name.toSet

val derefHits = cpg.call
  .name("<operator>.indirectFieldAccess", "<operator>.indirectIndexAccess")
  .argument(1).isIdentifier
  .filter(i => nullPtrs.contains(i.name))
  .l

// Pattern 2: bitwise & in condition with pointer comparison (binary_if variant)
val bitwiseHits = cpg.call.name("<operator>.and")
  .where(_.argument.isCall.name("<operator>.notEquals", "<operator>.equals"))
  .l

val detected = derefHits.nonEmpty || bitwiseHits.nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Two independent patterns unioned. Pattern 1 tracks NULL-assigned variables to dereference sites. Pattern 2 detects bitwise `&` in conditions containing equality comparisons.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | srcQL (6 detectors) | Built-in null analysis | CPG variable tracking |
| Patterns covered | 6 structural variants | Flow-sensitive null | Null-assign + bitwise-if |
| Interprocedural | Yes (PASS1 UNION/DIFF) | Partial | Yes (CPG) |
| False positive rate | 1 FP (smell_char_01b) | 0 FP | 0 FP |
| Recall | 100% | 100% | 33% |
