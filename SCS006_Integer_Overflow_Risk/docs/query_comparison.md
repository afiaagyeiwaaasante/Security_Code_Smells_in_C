# SCS006 — Query / Detection Method Comparison

**Smell:** Integer Overflow Risk
**CWE:** CWE-190 (Integer Overflow), CWE-191 (Integer Underflow)
**Operations covered:** addition (`+`), multiplication (`*`), increment (`++`)

---

## SmellDetect

**Mechanism:** srcML XML annotation + Python regex (no srcQL — srcQL does not reliably match binary arithmetic patterns)

Three detectors, each targeting one arithmetic operation:

### detect_unchecked_add.sh

**Sink pattern (Python regex):**
```python
ADD_OP_PATTERN = re.compile(
    r'<operator\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*\+\s*</operator>'
)
```

**Guard pattern:**
```python
MAX_PATTERN = re.compile(
    r'<name[^>]*>\s*(?:INT_MAX|CHAR_MAX|SHRT_MAX|UINT_MAX|INT64_MAX|LLONG_MAX)\s*</name>'
)
```

**Logic:** For each function block containing a `+` operator, check whether any `<condition>` element in the same block references a MAX constant. If no MAX guard is found → finding emitted.

### detect_unchecked_multiply.sh

**Sink pattern:**
```python
MUL_OP_PATTERN = re.compile(
    r'<operator\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*\*\s*</operator>'
)
```
Same guard check as above (MAX_PATTERN in `<condition>`).

### detect_unchecked_increment.sh

**Sink pattern:**
```python
INC_PATTERN = re.compile(
    r'<operator\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*\+\+\s*</operator>'
)
```
Same guard check as above.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains any of:
```
integerOverflow | signedIntegerOverflow | unsignedIntegerOverflow |
integerOverflowCast | shiftTooManyBits
```

**Result on test suite:** 0% recall — none of these IDs were emitted for the Juliet CWE-190/191 test cases. The Juliet patterns use `fscanf`-sourced data with no known upper bound, so cppcheck's value-range analysis cannot determine overflow is possible.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")

val arithOps = cpg.call
  .nameExact("<operator>.multiplication", "<operator>.addition",
              "<operator>.preIncrement", "<operator>.postIncrement")

val maxConstants = Set("INT_MAX","CHAR_MAX","SHRT_MAX","UINT_MAX","INT64_MAX","LLONG_MAX")

val guardedMethods = cpg.call
  .nameExact("<operator>.lessThan","<operator>.lessEqualsThan",
             "<operator>.greaterThan","<operator>.greaterEqualsThan")
  .argument
  .isIdentifier
  .filter(i => maxConstants.contains(i.name))
  .method.name.toSet

val hits = arithOps
  .filter(c => !guardedMethods.contains(c.method.name))
  .l

val detected = hits.nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Finds arithmetic operation nodes in methods that do not have a comparison against any MAX constant. Structurally equivalent to SmellDetect's approach but expressed as CPG traversal.

**Known issue:** Joern reports 11 FP on this test suite because functions containing arithmetic with no MAX guard are flagged regardless of whether the specific variable flowing into the arithmetic is bounded by other means (e.g., a literal initialiser or a range-limited input).

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | Python regex on srcML XML | Value-range analysis | CPG operator + guard traversal |
| Guard check | MAX constant in `<condition>` | Implicit (value range) | MAX constant in comparisons |
| Recall | 100% | 0% | 100% |
| Precision | 100% | N/A | 50% (11 FP) |
| srcQL used | No — arithmetic not reliably matched | N/A | N/A |
