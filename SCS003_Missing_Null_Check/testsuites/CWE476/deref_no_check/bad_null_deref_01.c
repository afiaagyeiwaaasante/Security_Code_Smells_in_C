/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : deref_no_check — bad (error level)
 * Smell    : pointer provably assigned NULL, dereferenced with no guard
 * Detector : Detector 3a (deref_no_check error)
 * Expected : error [nullPointer] [deref_no_check]
 *
 * Why this is bad:
 *   ptr is assigned NULL on the previous line. The dereference
 *   ptr->intOne is certain to crash. There is no null check anywhere
 *   in the function.
 */

#include "../testsuitesupport/std_testcase.h"

void bad_null_deref(void)
{
    twoIntsStruct *ptr = NULL;

    /* FLAW: ptr is NULL, no guard before dereference — certain crash */
    if (ptr->intOne == 5)
    {
        printLine("intOne == 5");
    }
}