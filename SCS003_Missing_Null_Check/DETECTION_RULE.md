# DETECTION_RULE.md
# SCS003 — Missing Null Check (CWE-476)

---

## 1. Smell Definition

| Field | Value |
|-------|-------|
| **Smell ID** | SCS003 |
| **Smell Name** | Missing Null Check |
| **CWE** | CWE-476: NULL Pointer Dereference |
| **Severity** | HIGH |
| **Language** | C |
| **Tool Chain** | srcML + srcSlice + XPath |

---

## 2. Description

A **Missing Null Check** occurs when a pointer variable is used or dereferenced without first verifying that it is not `NULL`. This smell is dangerous because dereferencing a null pointer causes undefined behavior, program crashes, or exploitable memory corruption.

### The specific pattern detected here:

Using the **bitwise AND operator `&`** instead of the **logical AND operator `&&`** in an if condition containing a pointer dereference. The bitwise `&` evaluates **both sides** of the expression regardless of the left-side result — meaning the right-hand pointer dereference occurs even when the pointer is `NULL`.

---

## 3. Code Pattern

### Bad (Vulnerable) — Detected as a smell
```c
twoIntsStruct *twoIntsStructPointer = NULL;

/* FLAW: single & causes both sides to be evaluated
 * even when twoIntsStructPointer is NULL          */
if ((twoIntsStructPointer != NULL) & (twoIntsStructPointer->intOne == 5)) {
    printLine("intOne == 5");
}
```

### Good (Safe) — Not flagged
```c
twoIntsStruct *twoIntsStructPointer = NULL;

/* FIX: && short-circuits — right side only evaluated
 * if left side is true                            */
if ((twoIntsStructPointer != NULL) && (twoIntsStructPointer->intOne == 5)) {
    printLine("intOne == 5");
}
```

---

## 4. Detection Approach

The detection uses a **two-stage approach**:

```
Stage 1: srcSlice JSON  →  Rule-based detection  →  Candidate variables
Stage 2: srcML XML      →  XPath confirmation    →  Confirmed sink
```

---

## 5. Stage 1 — Detection Rules (step1_detect.py)

Applied to the **srcSlice JSON** output for each variable in the program.

**All 4 rules must pass** for a variable to be flagged as a candidate.

### Rule 1 — Is a Pointer
```
variable["type"] contains "*"
```
- Ensures the variable is a pointer type
- Example: `twoIntsStruct*` ✅, `int` ❌

### Rule 2 — No Null Check (Empty Dependence)
```
variable["dependence"] == []
```
- srcSlice tracks what other variables/conditions a variable depends on
- An empty dependence list means no null check guards this variable
- This is the core indicator of the missing null check smell

### Rule 3 — Pointer Is Used
```
variable["use"] is not empty
```
- Confirms the pointer is actually referenced somewhere in the code
- A pointer that is never used cannot cause a null dereference
- Use locations are in `filename:line:col` format

### Rule 4 — In a Known Sink Function
```
variable["function"] contains a known sink name
```
- Filters to functions known to be vulnerable contexts
- Known sinks defined in `utils.py`:

| Sink Name | Description |
|-----------|-------------|
| `_bad` | Juliet Test Suite vulnerable function convention |
| `bad` | Generic vulnerable function name |
| `deref` | Explicit dereference function |
| `use_ptr` | Pointer usage function |
| `access` | Memory access function |

---

## 6. Stage 2 — XPath Sink Confirmation (step2_locate.py)

Applied to the **srcML XML** file using line numbers extracted from Stage 1 findings.

**All 3 checks must pass** to confirm the sink.

### Check 1 — Find if_stmt at Use Line
```xpath
//src:if_stmt[@pos:start[starts-with(.,'LINE:')]]
```
- Locates the `if_stmt` element whose `pos:start` attribute begins with the use line number
- Uses `@pos:start` (the if_stmt's own attribute) not `.//@pos:start` (any descendant)
- Example: line 25 → finds `<if_stmt pos:start="25:9">`

### Check 2 — Confirm Bitwise `&` Operator
```xpath
//src:if_stmt[@pos:start[starts-with(.,'LINE:')]]
    //src:operator[.='&']
```
- Searches inside the located `if_stmt` for an operator element with exact text `&`
- Distinguishes between `&` (bitwise AND — dangerous) and `&&` (logical AND — safe)
- If `&&` is used instead, this check fails and the sink is NOT confirmed

### Check 3 — Confirm `->` Dereference
```xpath
//src:if_stmt[@pos:start[starts-with(.,'LINE:')]]
    //src:operator[.='->']
```
- Confirms a pointer dereference (`->`) exists inside the same `if_stmt`
- Verifies the pointer is actually being accessed, not just compared

---

## 7. Stage 3 — Annotation (step3_annotate.py)

When both stages confirm the sink, the `if_stmt` element is annotated with a `sec:smell` attribute using the `security.smells` namespace.

### Annotation Format
```xml
<if_stmt xmlns:sec="security.smells"
         sec:smell="CWE476-null-pointer-dereference-binary-if-high"
         pos:start="25:9"
         pos:end="28:9">
    if ((twoIntsStructPointer != NULL) &
        (twoIntsStructPointer->intOne == 5))
    {
        printLine("intOne == 5");
    }
</if_stmt>
```

### Attribute Value Schema
```
CWE{number}-{smell-name}-{scenario}-{severity}

CWE476       → CWE number
null-pointer-dereference → smell name (kebab-case)
binary-if    → Juliet scenario variant
high         → severity level
```

---

## 8. Output Files

| File | Location | Description |
|------|----------|-------------|
| `*_findings.json` | `data/SliceFile/` | Stage 1 candidate variables |
| `*_annotated.xml` | `data/AttributeFile/` | Full XML with sec:smell attribute |
| `*_sink_element.xml` | `results/binary_if/` | Extracted sink if_stmt element |
| `*_sink_report.json` | `reports/SCS003_Missing_Null_Check/` | Stage 2 XPath check results |

---

## 9. Formal Detection Rule Summary

```
DETECT SCS003 (CWE-476) IF:

  FROM srcSlice JSON:
    variable.type          contains "*"     [Rule 1 — is pointer]
    variable.dependence    == []            [Rule 2 — no null check]
    variable.use           is not empty     [Rule 3 — pointer is used]
    variable.function      in KNOWN_SINKS   [Rule 4 — known sink]

  FROM srcML XML at variable.use[0] line:
    if_stmt                exists at line   [Check 1 — sink location]
    if_stmt operator       == "&"           [Check 2 — bitwise AND]
    if_stmt operator       == "->"          [Check 3 — dereference]

  THEN:
    smell    = "null-pointer-dereference"
    cwe      = "CWE-476"
    severity = "HIGH"
    annotate if_stmt with sec:smell attribute
```

---

## 10. Limitations

- Rule 2 (`dependence == []`) flags **both** bad and good functions since srcSlice does not distinguish the operator used — XPath Check 2 resolves this
- Rule 4 relies on function naming conventions from the Juliet Test Suite — real-world code may require extending `KNOWN_SINKS` in `utils.py`
- Currently detects the `binary_if` scenario — other Juliet variants (char, int, struct) require additional scenario-specific XPath checks

---

## 11. LaTeX for Overleaf

```latex
\subsection{SCS003: Missing Null Check (CWE-476)}

\subsubsection{Detection Rules}
\begin{table}[h]
\centering
\caption{Stage 1 Detection Rules for SCS003}
\begin{tabular}{|c|l|l|}
\hline
\textbf{Rule} & \textbf{Condition} & \textbf{Rationale} \\
\hline
Rule 1 & \texttt{type contains "*"} & Variable is a pointer \\
Rule 2 & \texttt{dependence == []} & No null check dependency \\
Rule 3 & \texttt{use} is not empty & Pointer is used in code \\
Rule 4 & function contains known sink & Vulnerable execution context \\
\hline
\end{tabular}
\label{tab:scs003-rules}
\end{table}

\subsubsection{XPath Sink Confirmation}
\begin{table}[h]
\centering
\caption{Stage 2 XPath Checks for SCS003}
\begin{tabular}{|c|l|l|}
\hline
\textbf{Check} & \textbf{Target} & \textbf{Purpose} \\
\hline
Check 1 & \texttt{if\_stmt} at use line & Locate the sink statement \\
Check 2 & \texttt{operator[.='\&']} & Confirm bitwise AND (not \&\&) \\
Check 3 & \texttt{operator[.='->']} & Confirm pointer dereference \\
\hline
\end{tabular}
\label{tab:scs003-xpath}
\end{table}
```