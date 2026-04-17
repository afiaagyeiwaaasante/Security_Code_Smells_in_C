/*
 * CWE-190 Integer Overflow Risk
 * Scenario : int64_t squaring — smell (warning level)
 * Source   : rand() — not user-controlled, internal only
 * Sink     : data * data with no overflow guard
 * Detector : unchecked_multiply
 * Expected : warning [integerOverflow] [unchecked_multiply]
 *
 * Why this is a smell and not a vulnerability:
 *   data is derived from rand(), not from user input. A wide type (int64_t)
 *   does not prevent overflow — data * data exceeds INT64_MAX when
 *   data > sqrt(INT64_MAX) (~3e9). The pattern is structurally fragile:
 *   replacing rand() with user-controlled input without a MAX guard
 *   converts this into a directly exploitable integer overflow.
 *
 * Compare: bad_int64_square_01.c — identical source; provided for explicit
 *   smell labelling and documentation alignment with the SCS003 pattern.
 */
#include <stdlib.h>
#include <stdint.h>

void smell_int64_square(void)
{
    int64_t data = (int64_t)rand();

    /* SMELL: no MAX guard, but source is not user-controlled */
    int64_t result = data * data;
    (void)result;
}
