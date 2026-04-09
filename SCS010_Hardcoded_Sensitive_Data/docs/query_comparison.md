# SCS010 — Query / Detection Method Comparison

**Smell:** Hardcoded Sensitive Data
**CWE:** CWE-259 (Use of Hard-coded Password), CWE-798
**Patterns covered:** `#define` credential macros, variable literals, `strcmp`/`strncmp` with literal

---

## SmellDetect

**Mechanism:** srcML XML annotation + Python regex (credential name matching + literal check)

Three detectors:

### detect_define_credential.sh

**Credential name pattern (Python regex):**
```python
CRED_NAME = re.compile(
    r'(?i)(?:password|passwd|pwd|secret|api.?key|token|credential|passphrase|private.?key)'
)
```

**Macro patterns:**
```python
MACRO_NAME_PAT = re.compile(r'<cpp:macro\b[^>]*>\s*<name[^>]*>([^<]+)</name>')
VALUE_PAT      = re.compile(r'<cpp:value[^>]*>([^<]*)</cpp:value>')
QUOTED_PAT     = re.compile(r'^"[^"]*"$')
```

**Logic:** For each `#define` macro whose name matches `CRED_NAME` and whose value is a quoted string literal → finding emitted.

### detect_password_literal.sh

**Patterns:**
```python
CRED_NAME   = re.compile(r'(?i)(?:password|passwd|pwd|secret|api.?key|token|...)')
DECL_FULL   = re.compile(r'<decl\b[^>]*pos:start="(\d+):(\d+)"[^>]*>(.*?)</decl>', re.DOTALL)
LITERAL_PAT = re.compile(r'<literal\s+type="string"[^>]*>')
INIT_PAT    = re.compile(r'<init\b[^>]*>(.*?)</init>', re.DOTALL)
```

**Logic:** For each variable declaration whose name matches `CRED_NAME` and whose initialiser contains a string literal → finding emitted.

### detect_strcmp_hardcoded.sh

**Patterns:**
```python
STRCMP_CALL = re.compile(
    r'<call\b[^>]*pos:start="(\d+):(\d+)"[^>]*>\s*<name[^>]*>\s*(?:strcmp|strncmp)\s*</name>',
    re.DOTALL
)
ARG_SPLIT   = re.compile(r'<argument\b[^>]*>(.*?)</argument>', re.DOTALL)
LITERAL_PAT = re.compile(r'<literal\s+type="string"[^>]*>')
```

**Logic:** For each `strcmp`/`strncmp` call, if any argument contains a string literal → finding emitted (hardcoded comparison value is the password).

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
| Query type | Python regex name + literal check | Built-in checker | CPG name + literal traversal |
| Credential name list | Regex: 9 terms (case-insensitive) | Built-in vocabulary | Same regex as SmellDetect |
| Patterns covered | `#define`, variable init, `strcmp` | Implicit | Variable assign + `strcmp` |
| Recall | 100% | 0% | 100% |
| Precision | 100% | N/A | 100% |
| Strategy equivalence | Equivalent to Joern | No | Equivalent to SmellDetect |
