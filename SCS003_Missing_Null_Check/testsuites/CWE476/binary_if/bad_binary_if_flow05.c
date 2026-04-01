/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : binary_if — flow variants 05-10 representative
 * Wrapper  : if(staticVar) — condition depends on a static variable
 *            that is never reassigned (always true or always false)
 * Detector : Detector 1 (binary_if)
 * Expected : error [nullPointer] [binary_if]
 *
 * Represents variants where the flaw is wrapped in a condition
 * that depends on a static variable initialized to true or false.
 * A tool should be able to identify that reads of these variables
 * always return their initialized values.
 * CONTAINS finds the inner pattern regardless of the static wrapper.
 *
 * Variants covered:
 *   05 — if(staticTrue)
 *   06 — if(staticFalse) — bad code in else branch
 */

#include "../testsuitesupport/std_testcase.h"

/* Never reassigned — always evaluates to true */
static int staticTrue  = 1;

/* Never reassigned — always evaluates to false */
static int staticFalse = 0;

void bad_binary_if_flow05(void)
{
    if (staticTrue)
    {
        twoIntsStruct *ptr = NULL;

        /* FLAW: & does not short-circuit */
        if ((ptr != NULL) & (ptr->intOne == 5))
        {
            printLine("intOne == 5");
        }
    }
}

void bad_binary_if_flow06(void)
{
    if (staticFalse)
    {
        /* dead code — flaw never reached */
        printLine("unreachable");
    }
    else
    {
        twoIntsStruct *ptr = NULL;

        /* FLAW: & does not short-circuit — flaw is in the else branch */
        if ((ptr != NULL) & (ptr->intOne == 5))
        {
            printLine("intOne == 5");
        }
    }
}