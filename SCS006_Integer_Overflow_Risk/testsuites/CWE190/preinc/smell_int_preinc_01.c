/*
 * CWE-190 Integer Overflow Risk
 * Scenario : pre-increment — smell (warning level)
 * Source   : internal constant (42) — not user-controlled
 * Sink     : ++data — no INT_MAX guard
 * Detector : unchecked_increment
 * Expected : warning [integerOverflow] [unchecked_increment]
 *
 * Why this is a smell and not a vulnerability:
 *   data is always 42 — no overflow occurs as written. The pattern is
 *   structurally fragile: replacing the constant with unvalidated user
 *   input converts this into an integer overflow vulnerability when
 *   data == INT_MAX (++INT_MAX wraps to INT_MIN, undefined behaviour).
 *
 * Compare: bad_int_preinc_01.c — same sink, rand() source → warning/smell
 *          (rand() is untainted; a fscanf source would give error/vulnerability)
 *
 * Smell form (this file):
 *   int data = 42;    // internally fixed — always safe
 *   ++data;           // SMELL: no INT_MAX guard
 */
#include <stdlib.h>

void smell_int_preinc(void)
{
    int data = 42;

    /* SMELL: pre-increment without INT_MAX guard — safe as written */
    ++data;
    (void)data;
}
