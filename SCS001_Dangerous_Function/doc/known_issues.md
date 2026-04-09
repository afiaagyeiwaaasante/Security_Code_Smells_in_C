# SCS001 — Known Issues and Limitations

## 1. Single-file analysis misses cross-file calls

**Issue:** When `gets()` is called inside a callee defined in a separate file,
running `smell_report.sh` on the caller alone produces no finding. The srcQL
query only sees the translation unit it is given.

**Example:**
```
bad_gets_interprocedural_62a.c  ← caller: read_input(buf)   → no gets() visible here
bad_gets_interprocedural_62b.c  ← callee: result = gets(dest) → smell is here
```

Running `smell_report.sh` on `62a.c` alone: **no finding**.
Running `smell_report.sh` on `62b.c` alone: **finding emitted** (but call site is in 62a).

**Workaround:** Use `smell_report_multi.sh` with both files. srcml combines them
into a single multi-unit archive and srcQL sees across the boundary.

---

## 2. Only one finding emitted per translation unit

**Issue:** The detector uses `head -1` when extracting call position, so only
the first `gets()` call in a function is reported. If a function contains
multiple calls to `gets()`, only one finding is written.

**Impact:** Low in practice — `gets()` is rarely called more than once in a
single function.

---

## 3. Macro-wrapped gets() calls are not detected

**Issue:** If `gets()` is hidden inside a preprocessor macro, srcml sees the
macro expansion result only if the file is pre-processed before parsing.
Without preprocessing, the call may not appear as a `<call>` node in the AST.

**Example:**
```c
#define READ_LINE(buf) gets(buf)
READ_LINE(dest);   /* not matched by the srcQL query */
```

---

## 4. Function pointer aliases are not detected

**Issue:** If `gets` is assigned to a function pointer and called through that
pointer, the call node name will be the pointer variable name, not `"gets"`.
The srcQL query `CONTAINS gets($DEST)` will not match.

**Example:**
```c
char *(*reader)(char *) = gets;
reader(dest);   /* not matched */
```

---

## 5. No severity gradation

**Issue:** All findings are emitted at `error` severity. There is no
distinction between `gets()` called on a small stack buffer (higher risk) vs a
large heap buffer (lower but still present risk).

---

## 6. Report output files accumulate

**Issue:** Each run of `smell_report.sh` writes a new timestamped report and
findings file to `results/<category>/`. Old runs are not cleaned up
automatically.

**Workaround:** Delete the `results/` directory manually between benchmark runs,
or use the output of the benchmark scripts (`evaluation/`, `cppcheck/results/`,
`joern/results/`) which overwrite on each run.
