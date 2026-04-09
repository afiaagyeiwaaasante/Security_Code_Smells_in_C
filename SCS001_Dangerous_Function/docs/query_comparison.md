# SCS001 — Query / Detection Method Comparison

**Smell:** Dangerous Function Use
**CWE:** CWE-242 (Use of Inherently Dangerous Function)
**Sink covered:** `gets()`

---

## SmellDetect

**Mechanism:** srcML XML annotation + srcQL structural query + XPath position extraction

**srcQL query:**
```
FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST)
```

Matches any function in the translation unit that contains a call to `gets()`.
`$DEST` binds to the destination buffer argument.

**XPath (position extraction):**
```xpath
//*[local-name()="call"]/*[local-name()="name"][.="gets"]/../@*[local-name()="start"]
```

**Detection logic:** Any match → finding emitted. `gets()` has no safe usage, so no guard check is needed.

**Interprocedural support:** `smell_report_multi.sh` combines source files into a single srcML archive before querying, enabling cross-file detection.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains `getsCalled`

**Notes:** cppcheck has a built-in `getsCalled` checker that fires unconditionally on any `gets()` call. No configuration required.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query:**
```scala
importCode("<source_path>")
val hits = cpg.call.name("gets").l
val detected = hits.nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Queries all call nodes in the CPG named `"gets"`. Any match → detected.

**Interprocedural support:** `importCode("<directory>")` builds a cross-file CPG, enabling detection across compilation units.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | srcQL structural | Built-in checker | CPG Scala query |
| Guard check needed | No — any `gets()` is unsafe | No | No |
| Interprocedural | Yes (multi-file archive) | Yes (multi-file args) | Yes (directory import) |
| Query expressiveness | Pattern-match on AST | Fixed checker | Traversal on CPG |
| Version sensitivity | srcML schema | cppcheck message IDs | Joern CPG node names |
