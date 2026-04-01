/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : deref_no_check — good
 * Fix      : null guard present before every dereference
 * Detector : Detector 3a and 3b (deref_no_check)
 * Expected : no detection
 */

#include "../testsuitesupport/std_testcase.h"

void good_guarded(void)
{
    twoIntsStruct *ptr = NULL;

    /* FIX: guard present — dereference only when ptr is not NULL */
    if (ptr != NULL)
    {
        if (ptr->intOne == 5)
        {
            printLine("intOne == 5");
        }
    }
}