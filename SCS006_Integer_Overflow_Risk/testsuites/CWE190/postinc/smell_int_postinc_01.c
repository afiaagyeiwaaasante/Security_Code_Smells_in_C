/*
 * CWE-190 Integer Overflow Risk
 * Scenario : post-increment — smell (warning level)
 * Source   : internal constant — not user-controlled
 * Sink     : data++ with no overflow guard
 * Detector : unchecked_increment
 * Expected : warning [integerOverflow] [unchecked_increment]
 *
 * Why this is a smell and not a vulnerability:
 *   data is initialised from a compile-time constant (42). The increment
 *   will never overflow in the current code. The pattern is structurally
 *   fragile: replacing the constant with user-supplied input without an
 *   INT_MAX guard converts this into a signed overflow vulnerability.
 *
 * Compare: bad_int_postinc_01.c — same sink, user-controlled source
 *   would produce → error/vulnerability once taint is wired in.
 */

void smell_int_postinc(void)
{
    int data = 42;

    /* SMELL: no INT_MAX guard, but data is not user-controlled */
    data++;
    (void)data;
}
