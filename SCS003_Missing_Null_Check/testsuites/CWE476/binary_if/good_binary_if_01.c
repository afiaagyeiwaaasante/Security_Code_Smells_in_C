/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : binary_if — good
 * Fix      : use logical && which short-circuits on NULL
 * Detector : Detector 1 (binary_if)
 * Expected : no detection
 *
 * Why this is safe:
 *   The && operator short-circuits. If ptr is NULL the left side
 *   evaluates to false and the right side is never evaluated.
 */
#include "../testsuitesupport/std_testcase.h"

void good_binary_if(void)
{
    twoIntsStruct *ptr = NULL;

    /* FIX: && short-circuits — ptr->intOne only evaluated when ptr != NULL */
    if ((ptr != NULL) && (ptr->intOne == 5))
    {
        printLine("intOne == 5");
    }
}