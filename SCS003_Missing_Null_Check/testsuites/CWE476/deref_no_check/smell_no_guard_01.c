/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : deref_no_check — smell (warning level)
 * Smell    : pointer assigned a non-NULL value but no null guard present
 *            before dereference — structurally fragile
 * Detector : Detector 3b (deref_no_check smell)
 * Expected : warning [missingNullCheck] [deref_no_check]
 *
 * Why this is a smell and not a vulnerability:
 *   ptr currently holds a valid address (&local) so the dereference
 *   is safe. However the absence of a null guard means any future
 *   change to ptr's source (e.g. a function that may return NULL)
 *   will introduce a crash without any syntactic warning. This is
 *   the definition of a security code smell — not yet exploitable
 *   but structurally risky.
 */

#include "../testsuitesupport/std_testcase.h"

void smell_no_guard(void)
{
    twoIntsStruct local = {0, 0};
    twoIntsStruct *ptr = &local;

    /* SMELL: ptr is valid now but no null guard — fragile pattern */
    if (ptr->intOne == 5)
    {
        printLine("intOne == 5");
    }
}