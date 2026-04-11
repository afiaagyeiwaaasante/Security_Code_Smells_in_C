# Query Complexity Comparison: SmellDetect vs Joern

> cppcheck uses built-in rule engines — analysts write no queries for it.

| SCS | Smell | SmellDetect (srcQL / XPath) | Joern (Scala CPG) |
|-----|-------|-------------------------------------|-------------------|
| SCS001 | Dangerous Function | `FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST)`  | `cpg.call.name("gets").l`  |
| SCS002 | Buffer Size Mismatch | 2 detectors: `malloc($A * $B)` and `$TYPE $SZ = $A * $B FOLLOWED BY malloc($SZ)`, both with Python `if.*SIZE_MAX` guard filter — **~2 lines srcQL + ~10 lines Python each** | `cpg.call.name("malloc").where(_.argument.isCall.name("<operator>.multiplication")).l` — **3 lines** (precomputed case needs separate set-subtraction traversal) |
| SCS003 | Missing Null Check | 4 detectors; each 1–3 srcQL clauses with `FOLLOWED BY` / `WHERE NOT` / `UNION` / `DIFFERENCE` — **~12 lines total** | CPG set-operations: `cpg.assignment.where(_.source.isLiteral.codeExact("0"))` → join to `indirectFieldAccess` traversal — **~10 lines** |
| SCS004 | Use After Free | 7 detectors; patterns like `free($PTR) FOLLOWED BY $CALL($PTR)` — **~14 lines total** | `cpg.call.name("free","delete").argument(1).isIdentifier.name` → join to `.inCall.nameNot("free","delete")` — **~6 lines** |
| SCS005 | Memory Leak Pattern | 3 detectors; srcQL `DIFFERENCE` expresses absence of `free`/`delete`; overwrite leak uses `$TYPE $PTR = malloc($A) FOLLOWED BY $PTR = malloc($B) DIFFERENCE ... FOLLOWED BY free($PTR) FOLLOWED BY ...`; XPath extracts positions — **srcQL + XPath only, no Python** | Set subtraction `mallocVars -- freedVars` across CPG traversals — **~8 lines** |
| SCS006 | Integer Overflow Risk | 2 srcQL detectors: `$TYPE $RESULT = $A * $B` and `$TYPE $RESULT = $A + $B`, each with XPath `count(<condition>[<name>=INT_MAX...])` guard filter; C++ destructor/constructor fallback via XPath `ancestor::` axis; increment detector XPath-only (`++` not expressible in srcQL) — **srcQL + XPath only, no Python** | CPG filter on `<operator>.multiplication` etc., cross-referenced against methods containing `INT_MAX` comparisons — **~12 lines** |
| SCS007 | Signed/Unsigned Confusion | `FIND $T $FUNC($PARAMS) {} CONTAINS malloc/memcpy/strncpy(...)` + XPath `count(<condition>[<operator>=>])` guard filter; destructor/constructor via XPath `ancestor::` fallback — **srcQL + XPath only, no Python** | Set subtraction: `sinkMethods -- guardedMethods` using `.greaterThan` traversals — **~10 lines** |
| SCS008 | Missing Format Specifier | srcQL `FIND $T $FUNC($PARAMS) {} CONTAINS printf/fprintf/syslog($FMT)` scopes to function; XPath guard: format arg non-literal + `count(fgets/getenv/scanf/fscanf) > 0`; destructor/constructor via XPath `ancestor::` fallback — **srcQL + XPath, no Python** | `.filter { c => !c.argument.order(1).exists(_.isLiteral) }` inline — **~8 lines** |
| SCS009 | Command Injection Risk | srcQL `FIND $T $FUNC($PARAMS) {} CONTAINS system/popen/execl($CMD)` scopes to function; XPath guard on result: first arg non-literal + `count(fgets/getenv) > 0`; destructor/constructor via XPath `ancestor::` fallback — **srcQL + XPath, no Python** | `.filter { c => !c.argument.order(1).exists(_.isLiteral) }` — same pattern as SCS008, no explicit taint tracking — **~8 lines** |
| SCS010 | Hardcoded Sensitive Data | XPath only: `<decl>[name contains cred keyword][<init>[<literal>][not(<call>)]]`; `<define>[macro/name contains cred][value starts-with '"']`; `<call>[strcmp][<arg>[<literal>]]` — credential keyword matching uses `translate()` for case-insensitive substring check — **XPath only, no Python, no srcQL** | `credPat.findFirstIn(l.name)` on `cpg.local`, joined to assignment literal check — **~12 lines** |

---

## Key Observations

**1. srcQL is closest to the smell description.**
Queries read almost like English — "find a function that contains `free(ptr)` followed by a call using `ptr`". No knowledge of an intermediate representation (IR) or graph node model is required. A security analyst who can describe the smell can write the query.

**2. Joern requires CPG expertise.**
Every query requires understanding Joern's Code Property Graph (CPG) node model: `<operator>.multiplication`, `indirectFieldAccess`, traversal APIs (`.argument`, `.inCall`, `.isIdentifier`). This is a significant upfront learning cost.

**3. SCS001 is the equal case.**
Both tools express `gets()` detection in one line. No flow reasoning is needed — a single call-name match suffices.

**4. All SCS detectors are now Python-free.**
SCS005–SCS010 are expressed entirely in srcQL + XPath — no Python. SCS008 and SCS009 both use srcQL to scope each detector to its matching function body, then apply two sequential XPath checks on the scoped result: (1) the critical argument is non-literal, and (2) a taint source (`fgets`, `getenv`, `scanf`, etc.) is present in the same function. Because srcQL pre-scopes the result, the taint check is a flat `count()` rather than the `ancestor::` predicate that pure XPath requires. SCS010 completes the Python-free conversion: XPath's `translate()` function provides case-insensitive substring matching, replacing Python's `re.compile(r'(?i)...')` for credential keyword scanning.

**5. XPath `translate()` replaces Python regex for keyword matching.**
XPath 1.0 has no regex support, but `contains(translate(.,'A-Z','a-z'),'keyword')` achieves the same case-insensitive substring matching as Python's `re.compile(r'(?i)keyword')`. This means all credential keyword checks in SCS010 are expressible without any Python. The tradeoff: 7 separate `contains()` calls replace one Python regex alternation group, making the XPath longer but eliminating the Python dependency entirely.
