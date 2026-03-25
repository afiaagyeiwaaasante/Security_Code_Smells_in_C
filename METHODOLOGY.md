# Methodology
> This file is structured for direct export to Overleaf (LaTeX).
> Each section maps to a thesis chapter or subsection.

---

## 1. Research Overview

This research detects and analyzes **security code smells** in C source code by combining:

- **Structural analysis** via srcML (XML representation of source code)
- **Data flow analysis** via srcSlice (program slicing)
- **Pattern querying** via srcQL/XPath
- **Annotation** via custom Python pipeline

A security code smell is a pattern in source code that indicates a potential vulnerability, even if it does not immediately cause a failure.

---

## 2. Tool Chain

### 2.1 srcML
srcML converts C/C++ source code into an XML representation that preserves syntactic structure and positional information.

```
Command:
    srcml --position --hash <input.c> -o <output.xml>

Key flags:
    --position   Adds line:column attributes to every XML element
    --hash       Adds a hash fingerprint to the unit for identification
```

### 2.2 srcSlice
srcSlice performs lightweight forward static slicing on srcML XML files. For every variable in the program, it produces a slice profile containing:

- `definition` — where the variable is defined (line:col)
- `use` — where the variable is used (line:col)
- `dependence` — variables this variable depends on
- `aliases` — pointer aliases
- `calls` — function calls involving the variable

```
Command:
    srcslice <input.xml> -o <output.json>
```

### 2.3 srcQL / XPath
srcQL and XPath are used to query the srcML XML for structural patterns, such as specific operators, function calls, or statement types at known line numbers.

---

## 3. Detection Pipeline

The detection pipeline consists of three steps:

```
Step 1: Rule-based detection on srcSlice JSON
Step 2: XPath-based sink location on srcML XML
Step 3: XML annotation with security smell attribute
```

### Step 1 — Rule-Based Detection (`step1_detect.py`)

Reads the srcSlice JSON output and applies detection rules to identify candidate variables.

**Detection rules for SCS003 (CWE-476):**

| Rule | Condition | Rationale |
|------|-----------|-----------|
| Rule 1 | `type contains "*"` | Variable must be a pointer |
| Rule 2 | `dependence == []` | No null check dependency exists |
| Rule 3 | `use` is not empty | Pointer is actually used in code |
| Rule 4 | `function` contains known sink | Execution context is vulnerable |

**Output:** A findings JSON file listing all candidate variables that satisfy all four rules.

### Step 2 — XPath Sink Location (`step2_locate.py`)

Takes the findings from Step 1 and uses XPath queries on the srcML XML to confirm the exact sink location.

**XPath checks:**

| Check | XPath Expression | Purpose |
|-------|-----------------|---------|
| Check 1 | `//src:if_stmt[@pos:start[starts-with(.,'LINE:')]]` | Locate if_stmt at use line |
| Check 2 | `//src:if_stmt//src:operator[.='&']` | Confirm bitwise & (not &&) |
| Check 3 | `//src:if_stmt//src:operator[.='->']` | Confirm pointer dereference |

**Output:** A sink report JSON file with XPath check results.

### Step 3 — XML Annotation (`step3_annotate.py`)

Annotates the confirmed sink element in the srcML XML with a `sec:smell` attribute using a custom `security.smells` namespace.

```xml
<if_stmt xmlns:sec="security.smells"
         sec:smell="CWE476-null-pointer-dereference-binary-if-high"
         pos:start="25:9"
         pos:end="28:9">
    ...
</if_stmt>
```

**Output:** Annotated XML file and extracted sink element XML file.

---

## 4. Security Code Smell Catalogue

| ID | Name | CWE | Operator Pattern | Severity |
|----|------|-----|-----------------|----------|
| SCS003 | Missing Null Check | CWE-476 | `&` instead of `&&` | HIGH |
| SCS001 | Buffer Overflow | CWE-121 | unchecked `strcpy`, `gets` | CRITICAL |
| SCS002 | Use After Free | CWE-416 | use after `free()` | HIGH |
| SCS004 | Integer Overflow | CWE-190 | unchecked arithmetic | MEDIUM |
| SCS005 | Format String | CWE-134 | uncontrolled format | HIGH |

---

## 5. Dataset

Test cases are sourced from the **NIST Juliet Test Suite for C/C++**:
- Source: https://samate.nist.gov/SARD/test-suites/116
- Each CWE contains multiple flow variants (e.g., `binary_if`, `char`, `int`)
- Each variant has a `_bad` (vulnerable) and `_good` (safe) function

---

## 6. Reproducibility

To reproduce all results:

```bash
# 1. Clone repository
git clone https://github.com/<your-username>/Security-Code-Smells.git
cd Security-Code-Smells

# 2. Install Python dependencies
pip3 install lxml --break-system-packages

# 3. Install srcML tools (see tools/README.md)

# 4. Run pipeline for SCS003 binary_if scenario
cd SCS003_Missing_Null_Check/src
python3 pipeline.py \
    ../data/SliceFile/CWE476_binary_if_01.json \
    ../data/XMLFile/CWE476_binary_if_01.xml \
    ../data/AttributeFile/CWE476_binary_if_01_annotated.xml
```

---

## 7. LaTeX Snippets for Overleaf

### Detection Rule Table
```latex
\begin{table}[h]
\centering
\caption{SCS003 Detection Rules for CWE-476}
\begin{tabular}{|c|l|l|}
\hline
\textbf{Rule} & \textbf{Condition} & \textbf{Rationale} \\
\hline
Rule 1 & \texttt{type contains "*"} & Variable is a pointer \\
Rule 2 & \texttt{dependence == []} & No null check exists \\
Rule 3 & \texttt{use} is not empty & Pointer is used in code \\
Rule 4 & function contains known sink & Vulnerable context \\
\hline
\end{tabular}
\label{tab:scs003-rules}
\end{table}
```

### Pipeline Figure
```latex
\begin{figure}[h]
\centering
\begin{verbatim}
C Source File
     |
     v
[srcml --position --hash]
     |
     v
srcML XML
     |
     v
[srcSlice]
     |
     v
Slice JSON
     |
     v
[step1_detect.py] -- Detection Rules
     |
     v
[step2_locate.py] -- XPath Checks
     |
     v
[step3_annotate.py] -- Annotation
     |
     v
Annotated XML + Report
\end{verbatim}
\caption{Security Code Smell Detection Pipeline}
\label{fig:pipeline}
\end{figure}
```

### Annotated XML Listing
```latex
\begin{lstlisting}[language=XML, caption={Annotated sink element for CWE-476}]
<if_stmt xmlns:sec="security.smells"
         sec:smell="CWE476-null-pointer-dereference-binary-if-high"
         pos:start="25:9">
  if ((twoIntsStructPointer != NULL) &
      (twoIntsStructPointer->intOne == 5))
</if_stmt>
\end{lstlisting}
```