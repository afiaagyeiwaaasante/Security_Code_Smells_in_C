# SCS010 — Query / Detection Method Comparison

**Smell:** Hardcoded Sensitive Data
**CWE:** CWE-259 (Use of Hard-coded Password), CWE-798
**Patterns covered:** `#define` credential macros, variable literals, `strcmp`/`strncmp` with literal

---

## SmellDetect

**Mechanism:** srcML XML annotation + XPath (credential name matching via `translate()` + literal check)

Three detectors, each a pure XPath expression — no Python, no srcQL.

### detect_define_credential.sh

**XPath expression:**
```xpath
//*[local-name()='define']
  [*[local-name()='macro']/*[local-name()='name']
    [contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                          'abcdefghijklmnopqrstuvwxyz'),'password') or
     contains(translate(.,...),'secret') or ...]]
  [starts-with(normalize-space(*[local-name()='value']),'"')]
/@*[local-name()='start']
```

**Logic:** Selects `<cpp:define>` elements whose macro `<name>` contains a credential keyword (case-insensitive via `translate()`) AND whose `<cpp:value>` starts with `"` (quoted string literal).

### detect_password_literal.sh

**XPath — Pattern 1 (declaration):**
```xpath
//*[local-name()='decl']
  [<credential-name-check-on-name-child>]
  [*[local-name()='init']
    [.//*[local-name()='literal'][@type='string'][string-length(.)>2]]
    [not(.//*[local-name()='call'])]]
/@*[local-name()='start']
```

**XPath — Pattern 2 (strcpy):**
```xpath
//*[local-name()='call']
  [*[local-name()='name'][.='strcpy']]
  [*[local-name()='argument_list']/*[local-name()='argument'][1]
    [.//*[local-name()='name'][<credential-name-check>]]]
  [*[local-name()='argument_list']/*[local-name()='argument'][2]
    [.//*[local-name()='literal'][@type='string']]]
/@*[local-name()='start']
```

**Logic:** Pattern 1 selects `<decl>` nodes whose direct `<name>` child contains a credential keyword AND whose `<init>` contains a string literal of length > 2 AND contains no `<call>` (guarding against `getenv()`-style initialisation). Pattern 2 selects `strcpy()` calls whose first argument variable name contains a credential keyword AND whose second argument is a string literal.

### detect_strcmp_hardcoded.sh

**XPath expression:**
```xpath
//*[local-name()='call']
  [*[local-name()='name'][.='strcmp' or .='strncmp']]
  [*[local-name()='argument_list']
    /*[local-name()='argument']
    [.//*[local-name()='literal'][@type='string']]]
/@*[local-name()='start']
```

**Logic:** Selects `strcmp`/`strncmp` calls where any `<argument>` contains a string literal — the literal is the hardcoded credential in the comparison.

---

## cppcheck

**Command:**
```bash
cppcheck --enable=all --suppress=missingIncludeSystem <file.c>
```

**Detection trigger:** stderr contains any of:
```
[hardcodedCredentials] | [hardcodedPassword]
```

**Result on test suite:** 0% recall. These checkers exist in newer cppcheck versions but were not triggered on the Juliet CWE-259 patterns. The Juliet patterns use simple `strcmp` comparisons with string literals — not the specific credential storage patterns cppcheck targets.

---

## Joern

**Command:**
```bash
joern --script <script.sc>
```

**Scala/CPG query (condensed):**
```scala
importCode("<source_path>")

val credPat = "(?i)(password|passwd|pwd|secret|api.?key|token|credential|passphrase|private.?key)".r

// 1. Local variables with credential names assigned a string literal
val varLiteral = cpg.local
  .filter(l => credPat.findFirstIn(l.name).isDefined)
  .filter { l =>
    val assigns = cpg.assignment
      .filter(a => a.target.code == l.name)
      .argument.order(2).isLiteral.l
    assigns.nonEmpty
  }

// 2. strcmp/strncmp with a string literal as any argument
val strcmpHard = cpg.call
  .nameExact("strcmp", "strncmp")
  .filter { c => c.argument.isLiteral.nonEmpty }

val detected = (varLiteral.l ++ strcmpHard.l).nonEmpty
println(s"JOERN_RESULT:$detected")
```

**Detection logic:** Two patterns unioned. Pattern 1 tracks credential-named local variables to their assignment sites and checks for literal values. Pattern 2 flags any `strcmp`/`strncmp` with a literal argument, regardless of the variable name.

---

## Comparison Summary

| Aspect | SmellDetect | cppcheck | Joern |
|---|---|---|---|
| Query type | XPath `translate()` name + literal check | Built-in checker | CPG name + literal traversal |
| Credential name list | XPath `translate()`: 7 terms (case-insensitive) | Built-in vocabulary | Same terms as SmellDetect |
| Patterns covered | `#define`, variable init, `strcmp` | Implicit | Variable assign + `strcmp` |
| Recall | 100% | 0% | 100% |
| Precision | 100% | N/A | 100% |
| Strategy equivalence | Equivalent to Joern | No | Equivalent to SmellDetect |
