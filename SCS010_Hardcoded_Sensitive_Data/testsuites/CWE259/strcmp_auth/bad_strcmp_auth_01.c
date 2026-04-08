/* bad_strcmp_auth_01.c
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * BAD: strcmp() used with a hardcoded string literal for authentication.
 * The secret is directly embedded in the comparison — visible to anyone
 * who can read the binary or source.
 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char input[64];
    if (fgets(input, sizeof(input), stdin) == NULL)
        return 1;
    input[strcspn(input, "\n")] = '\0';

    /* FLAW: password compared directly against a hardcoded string literal */
    if (strcmp(input, "s3cr3t!") == 0)
        puts("Access granted.");
    else
        puts("Access denied.");
    return 0;
}
