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