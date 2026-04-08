/* bad_password_var_01.c
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * BAD: password variable initialised to a string literal.
 * Juliet basis: CWE259_Hard_Coded_Password__w32_char_01 (adapted, cross-platform)
 */
#include <stdio.h>
#include <string.h>

int authenticate(const char *input)
{
    /* FLAW: hardcoded password stored in a variable */
    const char *password = "ABCD1234!";
    return strcmp(input, password) == 0;
}

int main(void)
{
    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    buf[strcspn(buf, "\n")] = '\0';

    if (authenticate(buf))
        puts("Access granted.");
    else
        puts("Access denied.");
    return 0;
}
