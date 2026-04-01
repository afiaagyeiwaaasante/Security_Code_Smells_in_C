/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : char — flow variants 01-03 representative
 * Sink     : array index dereference data[0] with no null guard
 * Detector : Detector 3 (null_deref) — array index query
 * Expected : error [nullPointer] [null_deref]
 *
 * Variants covered: 01 baseline, 02 if(1), 03 if(5==5)
 * CONTAINS finds the pattern regardless of wrapper depth.
 *
 * Note: declaration and assignment must be separate statements.
 * The srcQL pattern $PTR = NULL matches assignment expressions,
 * not declaration initializers (char *data = NULL).
 */
#include "../testsuitesupport/std_testcase.h"

void bad_char_null_deref(void)
{
    char *data;

    /* FLAW: Set data to NULL as a separate assignment */
    data = NULL;

    /* FLAW: data is NULL, no guard before data[0] — certain crash */
    printHexCharLine(data[0]);
}