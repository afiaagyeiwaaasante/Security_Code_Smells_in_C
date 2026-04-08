/* good_strcmp_auth_01.c
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * GOOD: strcmp() compares against a runtime value read from environment —
 * no hardcoded literal in the comparison.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void)
{
    /* FIX: password loaded from environment at runtime */
    const char *expected = getenv("APP_PASSWORD");
    if (expected == NULL) {
        fputs("APP_PASSWORD not set.\n", stderr);
        return 1;
    }

    char input[64];
    if (fgets(input, sizeof(input), stdin) == NULL)
        return 1;
    input[strcspn(input, "\n")] = '\0';

    /* FIX: comparison is against a runtime variable, not a literal */
    if (strcmp(input, expected) == 0)
        puts("Access granted.");
    else
        puts("Access denied.");
    return 0;
}
