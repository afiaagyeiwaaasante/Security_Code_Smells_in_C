/*
 * CWE-190 Integer Overflow Risk
 * Scenario : int multiplication — smell (warning level)
 * Source   : rand() — not user-controlled, internal only
 * Sink     : data * 2 with no overflow guard
 * Detector : unchecked_multiply
 * Expected : warning [integerOverflow] [unchecked_multiply]
 *
 * Why this is a smell and not a vulnerability:
 *   data comes from rand(), which is not attacker-controlled. The pattern
 *   is structurally fragile: wiring user input to data without a bounds
 *   check would make this directly exploitable — integer overflow flowing
 *   into a downstream malloc or array index enables heap corruption.
 *
 * Compare: bad_int_multiply_22a/b.c — same sink, fscanf source → error/vulnerability
 */
#include <stdlib.h>

void smell_int_multiply(void)
{
    int data = rand();

    /* SMELL: no MAX/2 guard, but source is not user-controlled */
    int result = data * 2;
    (void)result;
}
