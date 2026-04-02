/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : check_after_deref — bad (baseline)
 * Smell    : null check appears after the pointer has already been dereferenced
 * Detector : Detector 6 (check_after_deref)
 * Expected : warning [missingNullCheck] [check_after_deref]
 *
 * Why this is bad:
 *   malloc() can return NULL. The pointer is dereferenced before the null
 *   check is reached — if malloc fails, the program crashes on *ptr before
 *   the if(ptr != NULL) guard is ever evaluated. The check is misplaced
 *   and gives false confidence that the code is safe.
 */

#include "../testsuitesupport/std_testcase.h"
#include <stdlib.h>

void bad_check_after_deref(void)
{
    int *ptr = (int *)malloc(sizeof(int));

    /* FLAW: ptr dereferenced before null check — if malloc returned NULL this crashes */
    *ptr = 5;
    printIntLine(*ptr);

    /* NULL check is too late — ptr already dereferenced above */
    if (ptr != NULL)
    {
        *ptr = 10;
    }

    printIntLine(*ptr);
    free(ptr);
}
