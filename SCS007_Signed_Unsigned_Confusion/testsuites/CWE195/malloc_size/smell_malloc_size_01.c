/*
 * CWE-195 Signed-to-Unsigned Conversion Error
 * Scenario : malloc size — smell (warning level)
 * Source   : internal constant (42) — not user-controlled
 * Sink     : malloc(data) — signed int used as size, no positivity guard
 * Detector : signed_malloc
 * Expected : warning [signedUnsignedConversion] [signed_malloc]
 *
 * Why this is a smell and not a vulnerability:
 *   data is always 42 — a valid, positive allocation size. malloc() will
 *   never receive a wrapped size_t value in this code. The pattern is
 *   structurally fragile: changing the source from a constant to
 *   unvalidated user input (e.g. fscanf) without a positivity check
 *   allows a negative value to wrap to near-SIZE_MAX, enabling a
 *   subsequent heap overflow on any write into the buffer.
 *
 * Compare: bad_malloc_size_01.c — same sink, fscanf source → error/vulnerability
 *
 * Smell form (this file):
 *   int data = 42;              // internally fixed — always positive
 *   char *buf = malloc(data);   // SMELL: signed type, no positivity guard
 *
 * Vulnerability form (bad_malloc_size_01.c):
 *   fscanf(stdin, "%d", &data); // user-controlled — may be negative
 *   char *buf = malloc(data);   // FLAW: wraps to huge size_t
 */
#include <stdlib.h>
#include <string.h>

void smell_malloc_size(void)
{
    int data = 42;

    /* SMELL: signed int as malloc size, no positivity guard — currently safe */
    if (data < 100)
    {
        char *buf = (char *)malloc(data);
        if (buf == NULL) { return; }
        memset(buf, 'A', data - 1);
        buf[data - 1] = '\0';
        free(buf);
    }
}
