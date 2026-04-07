# SCS007 — CWE-195 Variants and Coverage

## Overview

CWE-195 (Use of Signed Type Where Unsigned Expected) describes a conversion
error where a signed integer — which may be negative — is implicitly or
explicitly converted to an unsigned type. When the signed value is negative,
the conversion wraps it to a very large positive number, which can cause heap
overflows, buffer overreads, or out-of-bounds memory operations.

The Juliet S01 test suite for CWE-195 contains **989 files** structured across
three orthogonal dimensions:

| Dimension | Values |
|-----------|--------|
| **Source** (how the signed int enters) | `connect_socket`, `fgets`, `fscanf` |
| **Sink** (how the signed value is misused) | `malloc`, `memcpy`, `memmove`, `strncpy` |
| **Flow** (structural data-flow variant) | 01–18, 21–22, 31–34, 41–45, 51–68, 72–74, 81–84 |

Rather than covering all 3 × 4 × 44 combinations, the test suite uses **5
focused groups** organised by **sink** — the most security-relevant dimension,
since the sink determines the exploitable consequence of the conversion error.

---

## Focused Groups (5)

### Group 1 — `malloc_size/`

**Pattern:** Signed integer passed as the size argument to `malloc()`.

```c
/* FLAW: if data < 0, (size_t)data wraps to a huge allocation */
char *buf = (char *)malloc(data);
```

**Fix:** Check `data > 0` before the allocation.

```c
if (data > 0) {
    char *buf = (char *)malloc(data);
}
```

**Security consequence:** A negative `data` value converts to a near-`SIZE_MAX`
allocation size, causing `malloc` to return NULL or succeed with an
under-allocated buffer, enabling heap overflow on subsequent writes.

**Sources covered:** `fgets`, `fscanf`, `connect_socket`

---

### Group 2 — `memcpy_count/`

**Pattern:** Signed integer passed as the byte count to `memcpy()` or `memmove()`.

```c
/* FLAW: if data < 0, (size_t)data wraps — copies gigabytes */
memcpy(dest, src, data);
```

**Fix:** Check `data > 0` and that `data <= sizeof(dest)` before copying.

```c
if (data > 0 && data <= (int)sizeof(dest)) {
    memcpy(dest, src, data);
}
```

**Security consequence:** Negative `data` wraps to a huge `size_t`, causing
`memcpy` to read far beyond the source buffer — a large-scale memory disclosure
or crash.

**Note:** `memmove()` is functionally identical to `memcpy()` for this pattern;
both pass a signed count to the same `size_t` parameter. `memmove` cases are
included in this group rather than given a separate folder.

**Sources covered:** `fgets`, `fscanf`, `connect_socket`

---

### Group 3 — `strncpy_count/`

**Pattern:** Signed integer passed as the character count to `strncpy()`.

```c
/* FLAW: if data < 0, (size_t)data wraps — copies past end of string */
strncpy(dest, src, data);
```

**Fix:** Check `data > 0` and bound it to `sizeof(dest) - 1`.

```c
if (data > 0 && data < (int)sizeof(dest)) {
    strncpy(dest, src, data);
}
```

**Security consequence:** Negative `data` wraps to a huge count, turning
`strncpy` into an unbounded string copy — a classic buffer overflow vector.

**Sources covered:** `fgets`, `fscanf`, `connect_socket`

---

### Group 4 — `interprocedural/`

**Pattern:** Signed value is received in one function (source) and passed
unchecked to a sink function in a separate file (Juliet flow 22a/22b).

```c
/* 22a — source file */
void CWE195_bad_source(int *data) {
    fscanf(stdin, "%d", data);          /* data may be negative */
}

/* 22b — sink file */
void CWE195_bad_sink(int data) {
    char *buf = (char *)malloc(data);   /* FLAW: no sign check */
}
```

**Fix:** The guard check must appear in the sink, or at the call site between
source and sink.

**Juliet flows covered:** 22a/22b (two-file source/sink split)

**Why it matters for detection:** Single-file detectors see the malloc call in
isolation without the tainted source — interprocedural analysis is required to
confirm the value may be negative. Multi-file srcML archives (`smell_report_multi.sh`)
are needed to detect this pattern.

---

### Group 5 — `cpp_class/`

**Pattern:** Signed value flows through a C++ class — stored as a member or
passed via a virtual method — before being used in a sink (Juliet flows 81–84).

| Flow | Mechanism |
|------|-----------|
| 81   | Virtual method dispatched via reference (`const Base& obj`) |
| 82   | Virtual method dispatched via pointer (`Base* obj`) |
| 83   | Value stored in constructor, used in destructor — object on stack |
| 84   | Value stored in constructor, used in destructor — object on heap |

```cpp
/* Flow 84 — heap allocation in destructor */
class SizeContainer {
    int storedData;
public:
    SizeContainer(int data) : storedData(data) {}
    ~SizeContainer() {
        /* FLAW: storedData may be negative */
        char *buf = (char *)malloc(storedData);
        free(buf);
    }
};
```

**Fix:** Guard in the destructor (or constructor) before using `storedData`.

**Why it matters:** These patterns test whether a detector handles C++ dispatch
and destructor bodies, not just plain C function bodies.

---

## Juliet Flow Reference

| Flow range | Type | Files per combination |
|------------|------|-----------------------|
| 01–18, 21  | Single-file, control-flow variants | 1 |
| 22a/22b    | Two-file interprocedural | 2 |
| 31–34      | Data via struct / pointer / reference | 1–2 |
| 41–45      | Data via function call chains | 1 |
| 51–68      | Deep multi-file chains (2–5 hops) | 2–5 |
| 72–74      | C++ STL containers (vector, list, deque) | 2 |
| 81–84      | C++ class virtual/ctor dispatch | 2–3 |

---

## Variants Not Covered

| Variant | Reason |
|---------|--------|
| `memmove` as a separate group | Detection pattern identical to `memcpy`; collapsed into `memcpy_count/` |
| Flows 31–34 (struct/pointer passing) | Structural complexity without new detection logic; covered by interprocedural group |
| Flows 51–68 (deep chains) | Multi-hop interprocedural; beyond scope of current srcML-based pipeline |
| Flows 72–74 (STL containers) | C++ template analysis not supported by srcML structural approach |
| CWE-196 (unsigned-to-signed) | Separate CWE; distinct detection pattern — future SCS007 extension |
