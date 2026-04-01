/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : interprocedural — good
 * Fix      : caller guards pointer before passing to callee
 * Detector : Detector 2 (interprocedural)
 * Expected : no detection
 */

#include "../testsuitesupport/std_testcase.h"

/* Callee: same as bad — dereferences without internal check */
void good_callee(twoIntsStruct *ptr)
{
    if (ptr->intOne == 5)
    {
        printLine("intOne == 5");
    }
}

/* Caller: guards the pointer before passing it */
void good_caller(void)
{
    twoIntsStruct *ptr = NULL;

    /* FIX: null check before calling good_callee */
    if (ptr != NULL)
    {
        good_callee(ptr);
    }
}