# SCS002 — Query / Detection Method Comparison

**Smell:** Buffer Size Mismatch
**CWE:** CWE-680 (Integer Overflow to Buffer Overflow)
**Sink covered:** `malloc(n * sizeof(T))` — size argument is a multiplication

---

## SmellDetect

**Mechanism:** srcML XML annotation + srcQL structural query + XPath position extraction

**srcQL query:**
```
FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * $B)
```

Matches any function containing a `malloc()` call whose size argument is a product expression. `$A` binds to the first operand (typically a count variable).

**XPath (position extraction):**
```xpath
//*[local-name()="call"]/*[local-name()="name"][.="malloc"]/../@*[local-name()="start"]
```

**Detection logic:** Any match → finding emitted. The multiplication itself is the smell; no overflow guard check is performed.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains any of:
```
integerOverflow | bufferAccessOutOfBounds | bufferOverflow
```

**Notes:** cppcheck detects this through value-range analysis. It must be able to infer that the product can overflow, so it may miss cases where operand bounds are unknown.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")
val hits = cpg.call.name("malloc")
  .where(_.argument.isCall.name("<operator>.multiplication"))
  .l
val detected = hits.nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Finds `malloc` call nodes whose argument subtree contains a multiplication operator node. Matches structurally — no value-range analysis.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | srcQL structural | Value-range analysis | CPG structural query |
| Guard check | No | Implicit (value range) | No |
| Interprocedural | Yes (multi-file archive) | Partial | Yes (directory import) |
| Query expressiveness | Pattern-match on AST | Semantic analysis | CPG operator node match |
| Misses | None on test suite | Count-unknown cases | None on test suite |
