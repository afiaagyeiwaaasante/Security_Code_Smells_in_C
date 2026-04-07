# SCS005 — Known Issues and Limitations

## False negatives (smells we miss)

### 1. Conditional allocation paths
If `malloc()` is only called on one branch of an `if`, and `free()` is called
on another branch, our detector may report a false positive (free present) or
miss the leak (free absent on the malloc branch).

```c
int *p = NULL;
if (flag) { p = malloc(n); }
// no free — but malloc only on one path
```
**Why**: The post-filter checks for any `free()` in the function, not per-branch.

### 2. Allocation in one function, free in another
If memory is allocated in one function and freed by the caller, our intra-
procedural detector will flag the callee as a leak.

```c
int *alloc_buf(int n) { return malloc(n); }  // flagged — no free here
void caller() { int *p = alloc_buf(10); free(p); }
```
**Why**: Detector 1 works per-function only.

### 3. `realloc` failure leak
`ptr = realloc(ptr, new_size)` — if `realloc` returns NULL, the original `ptr`
is lost. Our detector does not model this.

### 4. Error-path leaks through `goto`
Early exits via `goto cleanup` that skip a `free()` call are not tracked.
Our post-filter sees the `free()` in the function and considers it paired.

### 5. Loop-allocated, loop-freed mismatch
Memory allocated N times in a loop but freed once outside may appear correctly
paired to a structural query.

### 6. `new[]` / `delete[]` mismatch
The `new_no_delete` detector looks for `delete` presence; it does not verify
that `new[]` (array form) is matched with `delete[]` specifically.

---

## False positives (smells we over-report)

### 1. Functions that return the pointer to caller
A function that returns `malloc()`'d memory transfers ownership — it should
not be flagged as a leak.

```c
int *make_buf(int n) {
    return malloc(n * sizeof(int));  // ownership transferred — not a leak
}
```
**Mitigation**: The `overwrite_leak` detector is not affected; `no_free_on_exit`
may flag this. A return-value analysis pass would suppress it.

### 2. `calloc` / `realloc` — not covered by `malloc` query
Detector 1 queries only `malloc($SIZE)`. Allocations via `calloc()` or
`realloc()` on their own (not in the overwrite pattern) are not detected.

---

## Tool limitations

- One finding emitted per matched function block, not per allocation site
  if there are multiple leaked allocations in one function.
- Report accumulation: each run appends to the findings file if output dir
  is reused — use a timestamped output dir or clear it between runs.
