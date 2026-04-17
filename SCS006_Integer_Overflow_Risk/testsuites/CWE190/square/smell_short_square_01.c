/*
 * CWE-190 Integer Overflow Risk
 * Scenario : short squaring — smell (warning level)
 * Source   : internal constant (10 as short) — not user-controlled
 * Sink     : data * data — no SHRT_MAX guard
 * Detector : unchecked_multiply
 * Expected : warning [integerOverflow] [unchecked_multiply]
 *
 * Why this is a smell and not a vulnerability:
 *   data is always 10 — 10*10 = 100, well within short range (max 32,767).
 *   The pattern is structurally fragile: replacing the constant with
 *   unvalidated user input allows values near SHRT_MAX to overflow when
 *   squared (SHRT_MAX^2 = 1,073,676,289 > 32,767).
 *
 * Compare: bad_short_square_01.c — same sink, rand() source → warning/smell
 *          (rand() is untainted; a fscanf source would give error/vulnerability)
 *
 * Smell form (this file):
 *   short data = 10;              // internally fixed — always safe
 *   short result = data * data;   // SMELL: no SHRT_MAX guard
 */
#include <limits.h>

void smell_short_square(void)
{
    short data = 10;

    /* SMELL: data * data without SHRT_MAX guard — safe as written */
    short result = data * data;
    (void)result;
}
