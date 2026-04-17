# SmellDetect — Queries by Smell and Detector

| SCS | Smell | Detector | Query / Pattern |
|-----|-------|----------|-----------------|
| SCS001 | Dangerous Function | `dangerous_function` | `FIND $T $FUNC($PARAMS) {} CONTAINS gets($DEST)` |
| SCS002 | Buffer Size Mismatch | `buffer_size_mismatch` | `FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A * $B)` |
| SCS002 | Buffer Size Mismatch | `precomputed_size` | `FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $SZ = $A * $B FOLLOWED BY malloc($SZ)`  |
| SCS003 | Missing Null Check | `binary_if` | `FIND if(($PTR != NULL) & ($PTR->$FIELD == $VAL)) {}` |
| SCS003 | Missing Null Check | `null_deref` | `FIND $T $FUNC() {} CONTAINS $TYPE * $PTR = NULL FOLLOWED BY $PTR->$FIELD WHERE NOT (if($PTR != NULL) {})` |
| SCS003 | Missing Null Check | `missing_guard` | `FIND $T $FUNC() {} CONTAINS $PT * $PTR = $VAL FOLLOWED BY $PTR->$FIELD WHERE NOT (if($PTR != NULL) {})` |
| SCS003 | Missing Null Check | `interprocedural` | `FIND $RT $FNAME($PT * $PTR) {} CONTAINS $PTR->$FIELD WHERE NOT (if($PTR != NULL) {})`  |
| SCS004 | Use After Free | `use_after_free` | `FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY $CALL($PTR)` |
| SCS004 | Use After Free | `double_free` | `FIND $T $FUNC() {} CONTAINS free($PTR) FOLLOWED BY free($PTR)` |
| SCS004 | Use After Free | `new_delete_uaf` | `FIND $T $FUNC() {} CONTAINS delete $PTR FOLLOWED BY $CALL($PTR)` |
| SCS004 | Use After Free | `delete_array_uaf` | `FIND $T $FUNC() {} CONTAINS delete[] $PTR FOLLOWED BY $CALL($PTR)` |
| SCS004 | Use After Free | `return_freed_ptr` | `FIND $RT $FNAME($PARAMS) {} CONTAINS free($PTR) FOLLOWED BY return $PTR` |
| SCS004 | Use After Free | `operator_equals_uaf` | `FIND $RT operator=($PARAMS) {} CONTAINS delete[] $FIELD` |
| SCS004 | Use After Free | `interprocedural_uaf` | `FIND $RT $FNAME($PT * $PTR) {} CONTAINS free($PTR)` |
| SCS005 | Memory Leak | `no_free_on_exit` | `FIND $T $FUNC() {} CONTAINS malloc($SIZE) DIFFERENCE FIND $T $FUNC() {} CONTAINS free($PTR)` |
| SCS005 | Memory Leak | `overwrite_leak` | `FIND $T $FUNC() {} CONTAINS $TYPE $PTR = malloc($A) FOLLOWED BY $PTR = malloc($B) DIFFERENCE FIND $T $FUNC() {} CONTAINS $TYPE $PTR = malloc($A) FOLLOWED BY free($PTR) FOLLOWED BY $PTR = malloc($B)`|
| SCS005 | Memory Leak | `new_no_delete` | `FIND $T $FUNC() {} CONTAINS new $TYPE() DIFFERENCE FIND $T $FUNC() {} CONTAINS delete $PTR`  |
| SCS006 | Integer Overflow Risk | `unchecked_multiply` | `FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $RESULT = $A * $B`  |
| SCS006 | Integer Overflow Risk | `unchecked_add` | `FIND $T $FUNC($PARAMS) {} CONTAINS $TYPE $RESULT = $A + $B`|
| SCS006 | Integer Overflow Risk | `unchecked_increment` | XPath only: `//*[local-name()='operator'][.='++'][ancestor::function[not(condition/name=MAX)]]/@start`|
| SCS007 | Signed/Unsigned Confusion | `signed_malloc` | `FIND $T $FUNC($PARAMS) {} CONTAINS malloc($A)` |
| SCS007 | Signed/Unsigned Confusion | `signed_memcpy` | `FIND $T $FUNC($PARAMS) {} CONTAINS memcpy($A,$B,$C)` |
| SCS007 | Signed/Unsigned Confusion | `signed_strncpy` | `FIND $T $FUNC($PARAMS) {} CONTAINS strncpy($A,$B,$C)`  |
| SCS008 | Missing Format Specifier | `printf_direct` | srcQL: `FIND $T $FUNC($PARAMS) {} CONTAINS printf($FMT)` |
| SCS008 | Missing Format Specifier | `fprintf_direct` | srcQL: same as `printf_direct` with `fprintf`;  |
| SCS008 | Missing Format Specifier | `syslog_direct` | srcQL: same as `printf_direct` with `syslog`;  |
| SCS009 | Command Injection Risk | `system_tainted` | srcQL: `FIND $T $FUNC($PARAMS) {} CONTAINS system($CMD)`|
| SCS009 | Command Injection Risk | `popen_tainted` | srcQL: same as `system_tainted` with `popen` as sink |
| SCS009 | Command Injection Risk | `execl_tainted` | srcQL: `FIND $T $FUNC($PARAMS) {} CONTAINS execl($PATH)` (and `execlp`); XPath guard on result: first arg non-literal + `count(fgets/getenv) > 0`; destructor/constructor via XPath `ancestor::` fallback |
| SCS010 | Hardcoded Sensitive Data | `password_literal` | XPath: `<decl>[<name>contains cred keyword][<init>[<literal string>][not(<call>)]]`; fallback `<call>[strcpy][arg1 cred name][arg2 literal]` — **XPath only, no Python** |
| SCS010 | Hardcoded Sensitive Data | `define_credential` | XPath: `<define>[<macro/name contains cred keyword][starts-with(<value>,'"')]` — **XPath only, no Python** |
| SCS010 | Hardcoded Sensitive Data | `strcmp_hardcoded` | XPath: `<call>[strcmp/strncmp][<argument>[<literal string>]]` — **XPath only, no Python** |
