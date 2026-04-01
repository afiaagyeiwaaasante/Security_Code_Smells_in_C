/*
 * CWE-476 NULL Pointer Dereference
 * Scenario : interprocedural — char array index variant
 * Sink     : array index dereference data[0] in callee, no null check
 * Detector : Detector 2 (interprocedural)
 *
 * Demonstrates the two-level smell taxonomy:
 *
 *   bad_char_sink   — callee dereferences param with no null check
 *                     → warning: callee smell [missingNullCheck]
 *
 *   bad_char_caller — passes NULL explicitly, no guard before call
 *                     → error: null pointer [nullPointer]
 *
 *   smell_char_caller — passes non-NULL pointer, no guard before call
 *                       → warning: unguarded caller [missingNullCheck]
 *
 * Compare with bad_interprocedural_01.c which uses struct member (->)
 * This file uses array index ([]) — both are covered by the same detector
 */

#include "../testsuitesupport/std_testcase.h"

/* -----------------------------------------------------------------------
 * Callee: dereferences data[0] with no null check — callee smell
 * Any caller could pass NULL and crash
 * ----------------------------------------------------------------------- */
void bad_char_sink(char *data)
{
    /* SMELL: no null check before data[0] */
    printHexCharLine(data[0]);
}

/* -----------------------------------------------------------------------
 * Bad caller: passes NULL explicitly — error level
 * ----------------------------------------------------------------------- */
void bad_char_caller()
{
    char *data;

    /* FLAW: data assigned NULL then passed without guard */
    data = NULL;
    bad_char_sink(data);
}

/* -----------------------------------------------------------------------
 * Smell caller: passes non-NULL but without guard — warning level
 * The callee is still fragile — if data source changes to NULL it crashes
 * ----------------------------------------------------------------------- */
void smell_char_caller()
{
    char *data;

    /* SMELL: data assigned non-NULL but no guard before call */
    data = "Good";
    bad_char_sink(data);
}
