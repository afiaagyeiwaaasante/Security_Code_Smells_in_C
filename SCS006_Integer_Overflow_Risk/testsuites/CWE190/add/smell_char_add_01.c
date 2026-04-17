/*
 * CWE-190 Integer Overflow Risk
 * Scenario : char addition — smell (warning level)
 * Source   : rand() — not user-controlled, internal only
 * Sink     : data + 1 with no overflow guard
 * Detector : unchecked_add
 * Expected : warning [integerOverflow] [unchecked_add]
 *
 * Why this is a smell and not a vulnerability:
 *   data comes from rand(), which is not attacker-controlled. Overflow
 *   can only occur under internal conditions. The pattern is structurally
 *   fragile: replacing rand() with fscanf/fgets and wiring user input
 *   directly to the expression converts this smell into a vulnerability.
 *
 * Compare: bad_char_add_01.c — same sink, fscanf source → error/vulnerability
 */
#include <stdlib.h>
#include <limits.h>

void smell_char_add(void)
{
    char data = (char)(rand() % 64);

    /* SMELL: no MAX guard, but source is not user-controlled */
    char result = data + 1;
    (void)result;
}
