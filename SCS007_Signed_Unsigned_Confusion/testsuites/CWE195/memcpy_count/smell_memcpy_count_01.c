/*
 * CWE-195 Signed-to-Unsigned Conversion Error
 * Scenario : memcpy count — smell (warning level)
 * Source   : internal constant (50) — not user-controlled
 * Sink     : memcpy(dest, src, data) — signed int as byte count, no positivity guard
 * Detector : signed_memcpy
 * Expected : warning [signedUnsignedConversion] [signed_memcpy]
 *
 * Why this is a smell and not a vulnerability:
 *   data is always 50 — a valid, positive byte count. No wrap-around can
 *   occur in this code. The pattern is structurally fragile: replacing the
 *   constant with unvalidated user input allows a negative value to wrap
 *   to SIZE_MAX, causing memcpy to read arbitrarily beyond src — enabling
 *   memory disclosure or a crash.
 *
 * Compare: bad_memcpy_count_01.c — same sink, fscanf source → error/vulnerability
 *
 * Smell form (this file):
 *   int data = 50;                    // internally fixed — always positive
 *   memcpy(dest, src, data);          // SMELL: signed type, no positivity guard
 *
 * Vulnerability form (bad_memcpy_count_01.c):
 *   fscanf(stdin, "%d", &data);       // user-controlled — may be negative
 *   memcpy(dest, src, data);          // FLAW: wraps to SIZE_MAX
 */
#include <string.h>

void smell_memcpy_count(void)
{
    int data = 50;

    char src[100];
    char dest[100] = "";
    memset(src, 'A', sizeof(src) - 1);
    src[sizeof(src) - 1] = '\0';

    if (data < 100)
    {
        /* SMELL: signed int as byte count, no positivity guard — currently safe */
        memcpy(dest, src, data);
        dest[data] = '\0';
    }
}
