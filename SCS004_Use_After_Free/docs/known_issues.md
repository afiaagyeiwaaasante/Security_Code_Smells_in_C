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

## Multi-file variants — partial support

Basic cross-file interprocedural analysis is supported via
`smell_report_multi.sh`, which combines multiple source files into a
single srcML archive before running detectors. Longer call chains
distributed across three or more files may produce incomplete results
depending on how srcQL resolves cross-unit references in the combined
archive.

## False negative: free via function call

If the pointer is freed inside a helper function (not directly via
`free()` at the call site), the pipeline may not see the free. srcslice
does not model heap deallocation through opaque function calls.

## False negative: conditional free

When `free()` is called inside a branch (`if(cond) { free(ptr); }`) and
the pointer is used after the branch, the detector may miss the case if
the srcQL `FOLLOWED BY` query requires an unconditional free. Conditional
use-after-free patterns need a separate query variant.

## False negative: reassignment after free

If a pointer is freed and then reassigned to a new allocation before use,
the detector must not fire. Correct handling of this requires tracking
whether a `FOLLOWED BY` use is preceded by a reassignment. This is a
known query limitation and may produce false positives in some patterns.

## Double free via alias

When two pointer variables alias the same allocation and one frees it
while the other is used, the detector will miss the double free because
it tracks variable names, not allocation identities. srcslice alias
tracking is limited.
