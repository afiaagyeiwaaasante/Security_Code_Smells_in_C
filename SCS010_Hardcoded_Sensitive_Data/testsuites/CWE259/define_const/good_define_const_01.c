/* good_define_const_01.c
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * GOOD: no #define credential macro; password compared against runtime value.
 * Juliet basis: CWE259_Hard_Coded_Password__w32_char_13 goodG2B (adapted)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* FIX: no hardcoded password macro */
#define BUFSIZE 64

int main(void)
{
    /* FIX: read the expected password from an environment variable */
    const char *expected = getenv("APP_PASSWORD");
    if (expected == NULL) {
        fputs("APP_PASSWORD not set.\n", stderr);
        return 1;
    }

    char buf[BUFSIZE];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    buf[strcspn(buf, "\n")] = '\0';

    if (strcmp(buf, expected) == 0)
        puts("Access granted.");
    else
        puts("Access denied.");
    return 0;
}
