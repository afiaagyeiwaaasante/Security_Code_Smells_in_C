/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : interprocedural — bad
 * Smell    : callee dereferences pointer param with no null check;
 *            caller passes unguarded pointer to callee
 * Detector : Detector 2 (interprocedural)
 * Expected : error [nullPointer] [interprocedural]
 *
 * Why this is bad:
 *   bad_callee() dereferences its parameter with no null guard.
 *   bad_caller() declares a pointer, never checks it, and passes
 *   it directly to bad_callee(). If the pointer is NULL the
 *   dereference in bad_callee() crashes.
 */

#include "../testsuitesupport/std_testcase.h"

/* Callee: dereferences ptr with no null check — unsafe */
void bad_callee(twoIntsStruct *ptr)
{
    if (ptr->intOne == 5)
    {
        printLine("intOne == 5");
    }
}

/* Caller: passes unguarded pointer to bad_callee */
void bad_caller(void)
{
    twoIntsStruct *ptr;

    /* FLAW: no null check before passing ptr to bad_callee */
    bad_callee(ptr);
}