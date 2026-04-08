/* good_password_interprocedural_22b.c
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * GOOD: authentication uses a password read from environment — no literal.
 * Juliet basis: CWE259_Hard_Coded_Password__w32_char_22b goodG2B (adapted)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int CWE259_good_authenticate(const char *input, const char *expected)
{
    /* FIX: expected password comes from environment, not a literal */
    return strcmp(input, expected) == 0;
}

int main(void)
{
    const char *expected = getenv("APP_PASSWORD");
    if (expected == NULL) {
        fputs("APP_PASSWORD not set.\n", stderr);
        return 1;
    }

    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    buf[strcspn(buf, "\n")] = '\0';

    if (CWE259_good_authenticate(buf, expected))
        puts("Access granted.");
    else
        puts("Access denied.");
    return 0;
}
