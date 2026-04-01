/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : binary_if — flow variants 11-18 representative
 * Wrapper  : if(globalReturnsTrueOrFalse()) — runtime global function
 * Detector : Detector 1 (binary_if)
 * Expected : error [nullPointer] [binary_if]
 *
 * Key challenge for this variant:
 *   The bad function contains BOTH & (if branch) and && (else branch).
 *   A function-level query using DIFFERENCE would incorrectly subtract
 *   this function because it contains && elsewhere. The if-statement
 *   level query handles this correctly — & and && are structurally
 *   distinct tokens so the query matches only the bad if node.
 */

#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>

/* Simulates globalReturnsTrueOrFalse() from std_testcase.h */
static int globalReturnsTrueOrFalse(void) { return rand() % 2; }

void bad_binary_if_flow11(void)
{
    if (globalReturnsTrueOrFalse())
    {
        twoIntsStruct *ptr = NULL;

        /* FLAW: & does not short-circuit — ptr->intOne always evaluated */
        if ((ptr != NULL) & (ptr->intOne == 5))
        {
            printLine("intOne == 5");
        }
    }
    else
    {
        twoIntsStruct *ptr = NULL;

        /* FIX in this branch: && short-circuits safely */
        if ((ptr != NULL) && (ptr->intOne == 5))
        {
            printLine("intOne == 5");
        }
    }
}