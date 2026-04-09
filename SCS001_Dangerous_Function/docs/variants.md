# SCS001 — Query Variants and Extension Points

The current detector uses the srcQL pattern:

```
FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST)
```

This same query style can be extended to cover other dangerous C functions
by substituting the function name. The table below lists the functions and
the query variant that would detect each one.

---

## Dangerous functions coverable with this query style

| Function | Risk | Replacement | srcQL variant |
|----------|------|-------------|---------------|
| `gets(buf)` | No bounds check on input — always overflows | `fgets(buf, size, stdin)` | `CONTAINS gets($DEST)` ✓ current |
| `strcpy(dst, src)` | No length check — src may overflow dst | `strncpy(dst, src, n)` or `strlcpy` | `CONTAINS strcpy($DST, $SRC)` |
| `strcat(dst, src)` | No length check on dst — overflow if dst full | `strncat(dst, src, n)` or `strlcat` | `CONTAINS strcat($DST, $SRC)` |
| `sprintf(buf, fmt, ...)` | No bounds check on output buffer | `snprintf(buf, size, fmt, ...)` | `CONTAINS sprintf($BUF, $FMT)` |
| `vsprintf(buf, fmt, ap)` | Same as sprintf via va_list | `vsnprintf(buf, size, fmt, ap)` | `CONTAINS vsprintf($BUF, $FMT, $AP)` |
| `scanf("%s", buf)` | `%s` without width reads unbounded input | `scanf("%Ns", buf)` with explicit N | `CONTAINS scanf($FMT, $BUF)` |
| `sscanf(str, "%s", buf)` | Same risk from string input | `sscanf(str, "%Ns", buf)` | `CONTAINS sscanf($STR, $FMT, $BUF)` |

---

## Extension pattern

To add a new dangerous function to the detector, the query generalises directly:

```bash
QUERY='FIND $T $FUNC($PARAMS) {} CONTAINS strcpy($DST, $SRC)'
```

And the XPath call-site extraction changes only the function name:

```bash
CALL_POS=$(xmllint --xpath \
    '//*[local-name()="call"]/*[local-name()="name"][.="strcpy"]/../@*[local-name()="start"]' \
    "$TMPRESULT" 2>/dev/null | grep -o '[0-9][0-9]*:[0-9][0-9]*' | head -1)
```

---

## UNION queries for multiple functions in one pass

srcQL supports UNION, allowing all dangerous functions to be matched in a
single query. This avoids running multiple separate queries per file:

```
FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST)
UNION
FIND $T $FUNC($PARAMS) {} CONTAINS strcpy($DST, $SRC)
UNION
FIND $T $FUNC($PARAMS) {} CONTAINS strcat($DST, $SRC)
```

The XPath extraction would then need to iterate over each matched call name
to emit one finding per dangerous call site.

---

## Variants not coverable with this query style

| Scenario | Why the current pattern does not apply |
|----------|----------------------------------------|
| `scanf` with `%s` format string vulnerability | Danger depends on the format string argument value, not just the function name — requires data flow or string content analysis |
| Dangerous function called via function pointer | Call node name is the pointer variable, not the function name — requires alias analysis |
| Dangerous function inside a macro | Depends on preprocessing — srcml may not see the expanded call as a named `<call>` node |
