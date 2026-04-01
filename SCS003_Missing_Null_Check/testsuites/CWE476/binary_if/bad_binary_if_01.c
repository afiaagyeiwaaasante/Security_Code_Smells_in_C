/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : binary_if — bad
 * Smell    : bitwise & used instead of logical && in null-check condition
 * Detector : Detector 1 (binary_if)
 * Expected : error [nullPointer] [binary_if]
 *
 * Why this is bad:
 *   The & operator does not short-circuit. Both sides of the expression
 *   are always evaluated. When twoIntsStructPointer is NULL, the right
 *   side (twoIntsStructPointer->intOne) is evaluated anyway, causing
 *   a null pointer dereference.
 */

#include "../testsuitesupport/std_testcase.h"

void bad_binary_if(void)
{
    twoIntsStruct *ptr = NULL;

    /* FLAW: & does not short-circuit — ptr->intOne evaluated even when NULL */
    if ((ptr != NULL) & (ptr->intOne == 5))
    {
        printLine("intOne == 5");
    }
}