/* bad_define_const_01.c
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * BAD: password stored as a #define string literal macro.
 * Juliet basis: CWE259_Hard_Coded_Password__w32_char_13 (adapted, cross-platform)
 */
#include <stdio.h>
#include <string.h>

/* FLAW: hardcoded credential in preprocessor macro */
#define PASSWORD "ABCD1234!"

int main(void)
{
    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    buf[strcspn(buf, "\n")] = '\0';

    if (strcmp(buf, PASSWORD) == 0)
        puts("Access granted.");
    else
        puts("Access denied.");
    return 0;
}
