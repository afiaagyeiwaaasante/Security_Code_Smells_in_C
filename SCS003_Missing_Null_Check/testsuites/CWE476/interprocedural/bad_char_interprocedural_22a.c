/* tests/CWE476/interprocedural/bad_char_interprocedural_22a.c
 *
 * CWE-476 NULL Pointer Dereference
 * Scenario : interprocedural multi-file — char array index variant
 * Flow     : variant 22 — global variable controls sink execution,
 *            source and sink in separate files
 * Detector : Detector 2 (interprocedural) via smell_report_multi.sh
 *
 * This file contains the SOURCE (caller).
 * The SINK (callee) is in bad_char_interprocedural_22b.c
 *
 * Expected findings:
 *   22b.c: warning — bad_char_22_sink dereferences without null check
 *   22a.c: error   — bad_char_22_bad passes NULL to sink
 *   22a.c: warning — bad_char_22_smell passes unguarded ptr to sink
 */

#include "../testsuitesupport/std_testcase.h"

/* Global variable controls whether sink executes the dereference */
int bad_char_22_global = 0;

/* Forward declaration — sink defined in 22b */
void bad_char_22_sink(char *data);

/* Bad caller — assigns NULL, sets global true, calls sink */
void bad_char_22_bad(void)
{
    char *data;

    /* FLAW: data assigned NULL then passed to sink without guard */
    data = NULL;
    bad_char_22_global = 1;
    bad_char_22_sink(data);
}

/* Smell caller — assigns non-NULL, no guard before call */
void bad_char_22_smell(void)
{
    char *data;

    /* SMELL: data assigned but no null guard before passing to sink */
    data = "Good";
    bad_char_22_global = 1;
    bad_char_22_sink(data);
}