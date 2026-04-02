/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : binary_if — flow variant 02
 * Wrapper  : if(1) — literal true constant (always taken)
 * Detector : Detector 1 (binary_if)
 * Expected : error [nullPointer] [binary_if]
 *
 * Flow variant 02: the flaw is wrapped in a literal if(1) condition.
 * The tool should detect the inner binary_if pattern regardless of
 * the always-true outer wrapper.
 */

#include "../testsuitesupport/std_testcase.h"

void bad_binary_if_flow02(void)
{
    if (1)
    {
        twoIntsStruct *ptr = NULL;

        /* FLAW: & does not short-circuit — ptr->intOne always evaluated */
        if ((ptr != NULL) & (ptr->intOne == 5))
        {
            printLine("intOne == 5");
        }
    }
}
