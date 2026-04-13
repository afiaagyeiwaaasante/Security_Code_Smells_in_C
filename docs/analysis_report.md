# Security Code Smell Detection: Comprehensive Analysis Report

> **Generated:** 2026-04-12  
> **Source data:** raw evaluation JSON files across SCS001–SCS010  
> **Tools evaluated:** SmellDetect, cppcheck, Joern

---

## Analysis 1: Recall & Precision by Tool and Smell

| SCS | Smell | CWE | SD Recall | SD Precision | CPP Recall | CPP Precision | Joern Recall | Joern Precision |
|-----|-------|-----|-----------|--------------|------------|---------------|--------------|-----------------|
| SCS001 | Dangerous Function Use | 242 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| SCS002 | Buffer Size Mismatch | 680 | 100.0% | 100.0% | 0.0% | N/A | 87.5% | 63.6% |
| SCS003 | Missing NULL Check | 476 | 100.0% | 75.0% | 100.0% | 100.0% | 33.3% | 100.0% |
| SCS004 | Use-After-Free Risk | 416 | 100.0% | 100.0% | 75.0% | 100.0% | 75.0% | 50.0% |
| SCS005 | Memory Leak Pattern | 401 | 75.0% | 100.0% | 75.0% | 100.0% | 25.0% | 100.0% |
| SCS006 | Integer Overflow Risk | 190 | 100.0% | 100.0% | 0.0% | N/A | 100.0% | 50.0% |
| SCS007 | Signed/Unsigned Confusion | 195 | 100.0% | 100.0% | 0.0% | N/A | 100.0% | 100.0% |
| SCS008 | Missing Format Specifier | 134 | 100.0% | 100.0% | 0.0% | N/A | 100.0% | 100.0% |
| SCS009 | Command Injection Risk | 78 | 60.0% | 100.0% | 0.0% | N/A | 100.0% | 100.0% |
| SCS010 | Hardcoded Sensitive Data | 259 | 100.0% | 100.0% | 0.0% | N/A | 60.0% | 100.0% |

SmellDetect achieves perfect (100%) recall on 8/10 smells with a mean recall of 93.5%, compared to cppcheck at 35.0% (2/10 perfect) and Joern at 78.1% (5/10 perfect).

The largest recall divergences (>20 percentage points spread across tools) appear in: SCS002 (SD 100.0%, CPP 0.0%, Joern 87.5%); SCS003 (SD 100.0%, CPP 100.0%, Joern 33.3%); SCS004 (SD 100.0%, CPP 75.0%, Joern 75.0%); SCS005 (SD 75.0%, CPP 75.0%, Joern 25.0%); SCS006 (SD 100.0%, CPP 0.0%, Joern 100.0%); SCS007 (SD 100.0%, CPP 0.0%, Joern 100.0%); SCS008 (SD 100.0%, CPP 0.0%, Joern 100.0%); SCS009 (SD 60.0%, CPP 0.0%, Joern 100.0%); SCS010 (SD 100.0%, CPP 0.0%, Joern 60.0%). These cases highlight where tool depth — particularly flow reasoning and cross-file taint tracking — materially affects detection capability.

Precision diverges more sharply: SmellDetect achieves high precision across all smells, while Joern shows reduced precision on SCS006 (Integer Overflow) due to an over-broad guard pattern that flags arithmetic in any function containing a MAX comparison — a structural FP arising from the XPath guard mechanism.

---

## Analysis 2: Performance Trade-off

### Table 2a: Average Wall Time (seconds) per Tool per SCS

| SCS | Smell | SD avg (s) | CPP avg (s) | Joern avg (s) | Joern/SD ratio |
|-----|-------|-----------|------------|--------------|----------------|
| SCS001 | Dangerous Function Use | 0.245 | 0.002 | 3.538 | 14x |
| SCS002 | Buffer Size Mismatch | 0.271 | 0.000 | 3.705 | 14x |
| SCS003 | Missing NULL Check | 0.358 | 0.002 | 3.825 | 11x |
| SCS004 | Use-After-Free Risk | 0.346 | 0.003 | 3.776 | 11x |
| SCS005 | Memory Leak Pattern | 0.295 | 0.001 | 3.741 | 13x |
| SCS006 | Integer Overflow Risk | 0.306 | 0.000 | 3.660 | 12x |
| SCS007 | Signed/Unsigned Confusion | 0.304 | 0.001 | 3.631 | 12x |
| SCS008 | Missing Format Specifier | 0.301 | 0.002 | 3.684 | 12x |
| SCS009 | Command Injection Risk | 0.298 | 0.000 | 3.645 | 12x |
| SCS010 | Hardcoded Sensitive Data | 0.300 | 0.001 | 3.623 | 12x |

### Table 2b: Average Peak RSS (MB) per Tool per SCS

| SCS | Smell | SD avg (MB) | CPP avg (MB) | Joern avg (MB) | Joern/SD ratio |
|-----|-------|------------|-------------|---------------|----------------|
| SCS001 | Dangerous Function Use | 14.7 | 7.9 | 406.4 | 28x |
| SCS002 | Buffer Size Mismatch | 14.7 | 8.0 | 428.0 | 29x |
| SCS003 | Missing NULL Check | 14.7 | 7.8 | 431.4 | 29x |
| SCS004 | Use-After-Free Risk | 14.7 | 8.3 | 408.9 | 28x |
| SCS005 | Memory Leak Pattern | 14.7 | 7.9 | 417.2 | 28x |
| SCS006 | Integer Overflow Risk | 14.8 | 7.9 | 423.4 | 29x |
| SCS007 | Signed/Unsigned Confusion | 14.8 | 8.0 | 444.2 | 30x |
| SCS008 | Missing Format Specifier | 14.8 | 8.0 | 428.9 | 29x |
| SCS009 | Command Injection Risk | 14.8 | 7.9 | 412.6 | 28x |
| SCS010 | Hardcoded Sensitive Data | 15.0 | 8.0 | 425.2 | 28x |

SmellDetect's average wall time per test case is 0.30s, while Joern averages 3.68s — a **12x slowdown**. cppcheck is the fastest tool at sub-millisecond per-test times for most smells. The memory footprint tells a similar story: SmellDetect averages 15 MB peak RSS versus Joern's 423 MB — a **29x** increase. This reflects Joern's JVM-based Code Property Graph construction, which must parse and persist the full graph before querying. SmellDetect's structural srcQL/XPath approach avoids the graph build cost entirely, delivering recall parity with Joern on most smells at a fraction of the resource cost. The cost of depth — i.e., true data-flow reasoning via Joern — is justified only for smells where structural analysis systematically misses a class of FNs (e.g., interprocedural taint in SCS009).

---

## Analysis 3: Smell Detection Difficulty

| Rank | SCS | Smell | Best-tool Recall | Aggregate Recall | Difficulty |
|------|-----|-------|-----------------|-----------------|------------|
| 1 | SCS001 | Dangerous Function Use | 100.0% | 100.0% | **Easy** |
| 2 | SCS004 | Use-After-Free Risk | 100.0% | 83.3% | **Easy** |
| 3 | SCS003 | Missing NULL Check | 100.0% | 77.8% | **Easy** |
| 4 | SCS006 | Integer Overflow Risk | 100.0% | 66.7% | **Easy** |
| 5 | SCS007 | Signed/Unsigned Confusion | 100.0% | 66.7% | **Easy** |
| 6 | SCS008 | Missing Format Specifier | 100.0% | 66.7% | **Easy** |
| 7 | SCS002 | Buffer Size Mismatch | 100.0% | 62.5% | **Easy** |
| 8 | SCS009 | Command Injection Risk | 100.0% | 53.3% | **Easy** |
| 9 | SCS010 | Hardcoded Sensitive Data | 100.0% | 53.3% | **Easy** |
| 10 | SCS005 | Memory Leak Pattern | 75.0% | 58.3% | **Moderate** |

**Easy smells** (9): Dangerous Function Use (SCS001), Use-After-Free Risk (SCS004), Missing NULL Check (SCS003), Integer Overflow Risk (SCS006), Signed/Unsigned Confusion (SCS007), Missing Format Specifier (SCS008), Buffer Size Mismatch (SCS002), Command Injection Risk (SCS009), Hardcoded Sensitive Data (SCS010). These smells have syntactically distinctive patterns (banned functions, specific format strings, keyword-sensitive variable names) that all tools identify reliably with structural search.

**Moderate smells** (1): Memory Leak Pattern (SCS005). At least one tool achieves high recall, but inter-tool variance indicates the pattern lies at the edge of structural analysis capability.

---

## Analysis 4: Tool Complementarity

For each bad test case, we record which subset of tools detected it. This reveals where tools overlap vs. where running multiple tools adds coverage.

| SCS | Smell| All three| SmellDetect + Joern only| SmellDetect + cppcheck only| SmellDetect only| Joern only| cppcheck only| None detected|
|-----|------|-----------|--------------------------|-----------------------------|------------------|------------|---------------|---------------|
| SCS001 | Dangerous Function Use | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| SCS002 | Buffer Size Mismatch | 0 | 7 | 0 | 1 | 0 | 0 | 0 |
| SCS003 | Missing NULL Check | 1 | 0 | 2 | 0 | 0 | 0 | 0 |
| SCS004 | Use-After-Free Risk | 2 | 1 | 1 | 0 | 0 | 0 | 0 |
| SCS005 | Memory Leak Pattern | 1 | 0 | 1 | 1 | 0 | 1 | 0 |
| SCS006 | Integer Overflow Risk | 0 | 11 | 0 | 0 | 0 | 0 | 0 |
| SCS007 | Signed/Unsigned Confusion | 0 | 5 | 0 | 0 | 0 | 0 | 0 |
| SCS008 | Missing Format Specifier | 0 | 5 | 0 | 0 | 0 | 0 | 0 |
| SCS009 | Command Injection Risk | 0 | 3 | 0 | 0 | 2 | 0 | 0 |
| SCS010 | Hardcoded Sensitive Data | 0 | 3 | 0 | 2 | 0 | 0 | 0 |

Smells where all bad cases are detected by all three tools (single-tool coverage is sufficient): **SCS001**. These smells have highly syntactic patterns with no ambiguity across tools.

Smells where running a second tool recovers additional bad cases not caught alone: **SCS002 (7 extra cases), SCS003 (2 extra cases), SCS004 (2 extra cases), SCS005 (2 extra cases), SCS006 (11 extra cases), SCS007 (5 extra cases), SCS008 (5 extra cases), SCS009 (5 extra cases), SCS010 (3 extra cases)**. The highest complementarity gain comes from pairing SmellDetect with Joern for deep-taint smells (SCS009, SCS010), where Joern's flow graph captures interprocedural patterns and SmellDetect covers structural cases that Joern's graph build phase occasionally misses.

---

## Analysis 5: False Negative Root Cause Taxonomy

All false negatives (bad cases not detected) are catalogued below with their root cause. Root cause assignments use the authoritative notes provided with the dataset, supplemented by structural inspection of detection patterns.

| Tool | SCS | FN Test Case | Root Cause Type | Detail |
|------|-----|--------------|-----------------|--------|
| cppcheck | SCS002 | `bad_malloc_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS002 | `bad_malloc_fixed_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS002 | `bad_malloc_fgets_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS002 | `bad_malloc_rand_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS002 | `bad_malloc_precomputed_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS002 | `bad_malloc_return_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS002 | `bad_malloc_interproc_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS002 | `bad_malloc_struct_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| Joern | SCS002 | `bad_malloc_precomputed_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| Joern | SCS003 | `bad_null_deref_01` | Flow reasoning required | missing-guard and interprocedural patterns require flow reasoning |
| Joern | SCS003 | `bad_interprocedural_01` | Flow reasoning required | missing-guard and interprocedural patterns require flow reasoning |
| cppcheck | SCS004 | `bad_use_after_free_int_01` | Name-based tracking limitation | operator= pattern not detected by cppcheck |
| Joern | SCS004 | `bad_operator_equals_01` | Name-based tracking limitation | name-based tracking misses scope-reused variable names |
| SmellDetect | SCS005 | `bad_early_return_01` | Early-return / conditional path | conditional free on early-return path |
| cppcheck | SCS005 | `bad_new_no_delete_01` | Early-return / conditional path | conditional free on early-return path |
| Joern | SCS005 | `bad_early_return_01` | Early-return / conditional path | set-difference misses early-return and wrapper-freed pointers |
| Joern | SCS005 | `bad_overwrite_01` | Early-return / conditional path | set-difference misses early-return and wrapper-freed pointers |
| Joern | SCS005 | `bad_new_no_delete_01` | Early-return / conditional path | set-difference misses early-return and wrapper-freed pointers |
| cppcheck | SCS006 | `bad_int_multiply_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_char_add_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_unsigned_int_add_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_int64_square_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_short_square_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_int_postinc_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_int_preinc_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_int_multiply_81` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_int_multiply_82` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_int_multiply_83` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS006 | `bad_int_multiply_84` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS007 | `bad_malloc_size_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS007 | `bad_memcpy_count_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS007 | `bad_strncpy_count_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS007 | `bad_signed_malloc_22b` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS007 | `bad_signed_malloc_84` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS008 | `bad_printf_direct_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS008 | `bad_fprintf_direct_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS008 | `bad_env_format_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS008 | `bad_printf_interprocedural_22b` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS008 | `bad_printf_class_84` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| SmellDetect | SCS009 | `bad_system_interprocedural_22b` | Interprocedural / cross-file taint | interprocedural sink file (no taint source visible) + C++ class cross-block (fgets in constructor, system in destructor) |
| SmellDetect | SCS009 | `bad_system_class_84` | Interprocedural / cross-file taint | interprocedural sink file (no taint source visible) + C++ class cross-block (fgets in constructor, system in destructor) |
| cppcheck | SCS009 | `bad_system_console_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS009 | `bad_system_env_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS009 | `bad_popen_console_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS009 | `bad_system_interprocedural_22b` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS009 | `bad_system_class_84` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS010 | `bad_password_var_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS010 | `bad_define_const_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS010 | `bad_strcmp_auth_01` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS010 | `bad_password_interprocedural_22a` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| cppcheck | SCS010 | `bad_password_class_84` | Flow reasoning required | pattern not matched by this tool's analysis depth |
| Joern | SCS010 | `bad_define_const_01` | Preprocessor loss | #define macros expanded before CPG build + C++ class member assignment not captured by local variable traversal |
| Joern | SCS010 | `bad_password_class_84` | Preprocessor loss | #define macros expanded before CPG build + C++ class member assignment not captured by local variable traversal |

### Root Cause Summary

| Root Cause Type | Total FNs | SD | cppcheck | Joern |
|----------------|-----------|-----|----------|-------|
| Interprocedural / cross-file taint | 2 | 2 | 0 | 0 |
| Cross-block (ctor/dtor) | 0 | 0 | 0 | 0 |
| Preprocessor loss | 2 | 0 | 0 | 2 |
| Name-based tracking limitation | 2 | 0 | 1 | 1 |
| Early-return / conditional path | 5 | 1 | 1 | 3 |
| Value-range bounds unknown | 0 | 0 | 0 | 0 |
| Flow reasoning required | 42 | 0 | 39 | 3 |

The most frequent root cause is **Flow reasoning required** (42 FNs), reflecting limitations in structural analysis tools when patterns span function or file boundaries. **cppcheck** has the highest total FN count, driven primarily by flow-sensitive patterns that require CPG traversal beyond what the current query set implements. SmellDetect's FNs are concentrated in the interprocedural and cross-block categories — cases where the taint source is not syntactically co-located with the sink — suggesting targeted interprocedural extensions would yield the highest incremental recall gains.

---

## Analysis 6: Query Complexity vs Detection Effectiveness

| SCS | Smell | Detectors | Mechanism | Complexity | SD Recall | CPP Recall | Joern Recall |
|-----|-------|-----------|-----------|------------|-----------|------------|--------------|
| SCS001 | Dangerous Function Use | 1 | srcQL | Low | 100.0% | 100.0% | 100.0% |
| SCS002 | Buffer Size Mismatch | 2 | srcQL | Low | 100.0% | 0.0% | 87.5% |
| SCS003 | Missing NULL Check | 6 | srcQL | Low | 100.0% | 100.0% | 33.3% |
| SCS004 | Use-After-Free Risk | 7 | srcQL + FOLLOWED BY | Medium | 100.0% | 75.0% | 75.0% |
| SCS005 | Memory Leak Pattern | 3 | srcQL + XPath | Medium | 75.0% | 75.0% | 25.0% |
| SCS006 | Integer Overflow Risk | 3 | srcQL + XPath guard | Medium | 100.0% | 0.0% | 100.0% |
| SCS007 | Signed/Unsigned Confusion | 3 | srcQL + XPath guard | Medium | 100.0% | 0.0% | 100.0% |
| SCS008 | Missing Format Specifier | 3 | srcQL + XPath + taint | High | 100.0% | 0.0% | 100.0% |
| SCS009 | Command Injection Risk | 3 | srcQL + XPath + taint | High | 60.0% | 0.0% | 100.0% |
| SCS010 | Hardcoded Sensitive Data | 3 | pure XPath (srcQL not applicable) | High | 100.0% | 0.0% | 60.0% |

### Conceptual Scatter: Complexity vs SmellDetect Recall

```
SD Recall
  100% |
  Low    |   SCS001(*)  SCS002(*)  SCS003(*)
  Medium |   SCS004(*)  SCS005(o)  SCS006(*)  SCS007(*)
  High   |   SCS008(*)  SCS009(o)  SCS010(*)
         +----------- Complexity Tier (Low -> High)
  Legend: * = Easy (>=90%), o = Moderate (60-89%), x = Hard (<60%)
```

Note: SCS010 appears in the High tier because its pure XPath expressions are structurally complex (`translate()` keyword matching, multi-predicate `<define>` and `<decl>` guards), but for a different reason than SCS008/SCS009 — srcQL **cannot** be used for SCS010 at all. `#define` declarations fall outside any function body, making the `FIND $T $FUNC() {} CONTAINS ...` form inapplicable, and credential keyword matching requires case-insensitive substring checks that srcQL does not support. The High complexity rating reflects XPath complexity, not an srcQL+XPath combination.

Across the three complexity tiers, SmellDetect recall averages: Low=100.0%, Medium=93.8%, High=86.7%. The Pearson correlation between number of detectors and SmellDetect recall is **r = 0.11**, indicating essentially no linear correlation between query count and recall.

This suggests **diminishing returns** from adding more detectors: SCS001 (1 detector, srcQL) achieves the same perfect recall as SCS004 (7 detectors, srcQL + FOLLOWED BY). The recall ceiling for a given smell is primarily set by whether the pattern is syntactically observable, not by how many detectors are employed. Adding detectors increases coverage of pattern variants (e.g., `new`/`delete` vs `malloc`/`free`), but does not overcome the fundamental limitation of structural analysis against interprocedural, macro-expanded, or constructor/destructor-split patterns.

---

*End of report.*
