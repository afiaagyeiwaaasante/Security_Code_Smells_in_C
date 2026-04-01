/* tests/CWE476/interprocedural/bad_char_interprocedural_22b.c
 *
 * CWE-476 NULL Pointer Dereference
 * Scenario : interprocedural multi-file — char array index variant
 * Flow     : variant 22 — sink file
 *
 * This file contains the SINK (callee).
 * The SOURCE (caller) is in bad_char_interprocedural_22a.c
 *
 * Expected finding:
 *   warning — bad_char_22_sink dereferences data[0] without null check
 */

#include "../testsuitesupport/std_testcase.h"

extern int bad_char_22_global;

/* Sink: dereferences data[0] when global is true — no null check */
void bad_char_22_sink(char *data)
{
    if (bad_char_22_global)
    {
        /* SMELL: no null check before data[0] */
        printHexCharLine(data[0]);
    }
}