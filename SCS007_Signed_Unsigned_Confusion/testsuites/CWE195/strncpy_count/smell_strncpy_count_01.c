/*
 * CWE-195 Signed-to-Unsigned Conversion Error
 * Scenario : strncpy count — smell (warning level)
 * Source   : internal constant (30) — not user-controlled
 * Sink     : strncpy(dest, src, data) — signed int as char count, no positivity guard
 * Detector : signed_strncpy
 * Expected : warning [signedUnsignedConversion] [signed_strncpy]
 *
 * Why this is a smell and not a vulnerability:
 *   data is always 30 — a valid, positive character count. No wrap-around
 *   occurs in this code. The pattern is structurally fragile: replacing the
 *   constant with unvalidated user input converts strncpy into an unbounded
 *   copy, enabling buffer overflow.
 *
 * Compare: bad_strncpy_count_01.c — same sink, fscanf source → error/vulnerability
 *
 * Smell form (this file):
 *   int data = 30;                    // internally fixed — always positive
 *   strncpy(dest, src, data);         // SMELL: signed type, no positivity guard
 *
 * Vulnerability form (bad_strncpy_count_01.c):
 *   fscanf(stdin, "%d", &data);       // user-controlled — may be negative
 *   strncpy(dest, src, data);         // FLAW: wraps to SIZE_MAX → unbounded copy
 */
#include <string.h>

void smell_strncpy_count(void)
{
    int data = 30;

    char src[100];
    char dest[100] = "";
    memset(src, 'A', sizeof(src) - 1);
    src[sizeof(src) - 1] = '\0';

    if (data < 100)
    {
        /* SMELL: signed int as char count, no positivity guard — currently safe */
        strncpy(dest, src, data);
        dest[data] = '\0';
    }
}
