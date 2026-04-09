# SCS007 — Query / Detection Method Comparison

**Smell:** Signed/Unsigned Confusion
**CWE:** CWE-194 (Unexpected Sign Extension), CWE-195 (Use of Signed Type Where Unsigned Expected)
**Sinks covered:** `malloc`, `memcpy`, `memmove`, `strncpy`

---

## SmellDetect

**Mechanism:** srcML XML annotation + Python regex (block-scoped guard check)

Three detectors, each targeting one sink function:

### detect_signed_malloc.sh

**Sink pattern (Python regex):**
```python
MALLOC_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*malloc\s*</name>',
    re.DOTALL
)
```

**Guard pattern:**
```python
POSITIVE_GUARD = re.compile(r'&gt;', re.DOTALL)
```

**Logic:** For each function/constructor/destructor block containing `malloc`, extract all `<condition>` elements. If any condition contains `&gt;` (the XML-escaped `>` operator) → guard present, skip. Otherwise → finding emitted.

`&gt;` covers: `data > 0`, `data >= 1`, `data > 0 && data <= MAX`.

### detect_signed_memcpy.sh / detect_signed_strncpy.sh

Same logic, sink patterns match `memcpy|memmove` and `strncpy` respectively.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains any of:
```
signConversion | negativeIndex | bufferAccessOutOfBounds | argumentSize
```

**Result on test suite:** 0% recall — none of these IDs were emitted. The Juliet patterns use `fscanf`-sourced signed integers; cppcheck does not track the sign of function return values into size arguments without explicit annotations.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")

val sinkMethods = cpg.call
  .nameExact("malloc", "memcpy", "memmove", "strncpy")
  .method.name.toSet

val guardedMethods = cpg.call
  .nameExact("<operator>.greaterThan", "<operator>.greaterEqualsThan")
  .where(_.argument.isLiteral.filter(l => l.code == "0" || l.code == "1"))
  .method.name.toSet

val hits = cpg.call
  .nameExact("malloc", "memcpy", "memmove", "strncpy")
  .filter(c => !guardedMethods.contains(c.method.name))
  .l

val detected = hits.nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Finds sink calls in methods that do not contain a `>` or `>=` comparison against the literal `0` or `1`. Structurally equivalent to SmellDetect but expressed as CPG method-level filtering.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | Python regex on srcML XML | Type-flow analysis | CPG method-level guard filter |
| Guard check | `&gt;` in `<condition>` element | Implicit (type flow) | `>` / `>=` against literal 0 or 1 |
| Block granularity | Per function/constructor/destructor | Per translation unit | Per method |
| Recall | 100% | 0% | 100% |
| Precision | 100% | N/A | 100% |
