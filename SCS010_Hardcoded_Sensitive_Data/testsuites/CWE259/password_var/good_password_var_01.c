/* good_password_var_01.c
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * GOOD: password read from the environment at runtime — not hardcoded.
 * Juliet basis: CWE259_Hard_Coded_Password__w32_char_01 goodG2B (adapted)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int authenticate(const char *input, const char *password)
{
    /* FIX: password supplied externally — not a string literal */
    return strcmp(input, password) == 0;
}

int main(void)
{
    /* FIX: read password from environment variable, not a literal */
    const char *password = getenv("APP_PASSWORD");
    if (password == NULL) {
        fputs("APP_PASSWORD not set.\n", stderr);
        return 1;
    }

    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    buf[strcspn(buf, "\n")] = '\0';

    if (authenticate(buf, password))
        puts("Access granted.");
    else
        puts("Access denied.");
    return 0;
}
