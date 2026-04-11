# SCS006 — Query / Detection Method Comparison

**Smell:** Integer Overflow Risk
**CWE:** CWE-190 (Integer Overflow), CWE-191 (Integer Underflow)
**Operations covered:** addition (`+`), multiplication (`*`), increment (`++`)

---

## SmellDetect

**Mechanism:** srcQL structural query + Python guard filter (hybrid)

Three detectors, each targeting one arithmetic operation:

### detect_unchecked_multiply.sh

**srcQL query:**
```
FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $RESULT = $A * $B
```

Narrows to functions and class methods whose body contains a typed declaration
whose RHS is a product expression. C++ `<destructor>` and `<constructor>` elements
have no return type in srcML, so those are scanned from the original XML directly
via Python regex fallback (`<operator>*</operator>` in each destructor/constructor block).

**Guard filter (Python):**
```python
MAX_PATTERN = re.compile(
    r'<name[^>]*>\s*(?:INT_MAX|CHAR_MAX|SHRT_MAX|UINT_MAX|INT64_MAX|LLONG_MAX)\s*</name>'
)
conditions = re.findall(r'<condition\b[^>]*>.*?</condition>', block, re.DOTALL)
if any(MAX_PATTERN.search(c) for c in conditions):
    continue  # guarded — skip
```

### detect_unchecked_add.sh

**srcQL query:**
```
FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $RESULT = $A + $B
```

Same hybrid strategy as the multiply detector: srcQL for regular functions/methods,
Python fallback for destructor/constructor blocks.

Same `MAX_PATTERN` guard check in `<condition>` elements.

**Edge case:** `bad_unsigned_int_add` initialises `data = UINT_MAX` in a `<decl>`
initialiser, not in a `<condition>`. The guard check only counts MAX inside
`<condition>`, so this initialiser does not suppress the finding correctly.

### detect_unchecked_increment.sh

**Strategy:** Python regex only (no srcQL).

`data++` and `++data` are standalone expression statements, not typed declarations.
srcQL's `$TYPE $RESULT = ...` pattern cannot match them. The detector scans
`<operator>++</operator>` elements directly in the XML.

**Sink pattern:**
```python
INC_PATTERN = re.compile(
    r'<operator\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*\+\+\s*</operator>'
)
```
Same MAX guard check in `<condition>` elements.

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
