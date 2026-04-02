/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : deref_after_check — bad (baseline)
 * Smell    : pointer dereferenced inside the if(ptr == NULL) branch
 * Detector : Detector 5 (deref_after_check)
 * Expected : error [nullPointer] [deref_after_check]
 *
 * Why this is bad:
 *   The if condition explicitly confirms ptr IS NULL, then the body
 *   dereferences ptr anyway — guaranteed null pointer dereference.
 */

#include "../testsuitesupport/std_testcase.h"

void bad_deref_after_check(void)
{
    int *ptr = NULL;

    /* FLAW: ptr is confirmed NULL by the condition, then dereferenced inside */
    if (ptr == NULL)
    {
        printIntLine(*ptr);
    }
}
