# Known issues and limitations

## srcattributor path sensitivity

srcattributor resolves the srcML file via the `file` path embedded
in the srcslice JSON at the time srcslice runs. This means:

- Do not move source files between stage 2 and stage 3
- Do not use `/tmp` as an intermediate directory
- Always run `smell_report.sh` from the project root with a stable
  relative path to the source file

## srcattributor version mismatch

The `--help` output for srcattributor on the current release shows
only `-i` (JSON) and `-o` (XML). The main branch documentation shows
a two-positional-argument form. Use the `-i` / `-o` flag form until
the new release is tagged.

## Multi-file variants not supported

Juliet variants 51–54 distribute the flaw across multiple files
(54a.c calls 54b.c etc.). The current pipeline handles single-file
cases only.

## False negative: NULL assigned via function return

If NULL reaches the pointer via a function return rather than direct
assignment, srcslice may not produce a `slice:use` link on the
condition expression, and the detector will miss it.

## NULL propagation via local copy (Juliet variant 31)

When NULL is assigned to `data` and then copied to a new variable
(`dataCopy = data`), `detect_null_deref` does not follow the copy —
it tracks only the original variable name. `detect_missing_guard` does
fire on the unguarded dereference of `dataCopy` but classifies it as
`warning` rather than `error` since it has no NULL assignment evidence.
Test case: `testsuites/CWE476/struct/bad_struct_copy_01.c`

## False negative: NULL via pointer-to-pointer (Juliet variant 32)

When NULL is written through a pointer-to-pointer (`*dataPtr = NULL`)
and retrieved via the original variable (`data = *dataPtr`), no
detector fires. The pipeline has no model of pointer indirection so
it cannot connect the write through `dataPtr` to the dereference of
`data`. This is a complete false negative.
Test case: `testsuites/CWE476/struct/bad_struct_ptr_to_ptr_01.c`

## NULL propagation via union aliasing (Juliet variant 34)

When NULL flows into one union member (`unionFirst`) and is read back
via another (`unionSecond`), `detect_null_deref` misses it — the
pipeline has no model of union aliasing. `detect_missing_guard` does
fire on the unguarded dereference of the retrieved pointer but at
`warning` severity only.
Test case: `testsuites/CWE476/struct/bad_struct_union_01.c`