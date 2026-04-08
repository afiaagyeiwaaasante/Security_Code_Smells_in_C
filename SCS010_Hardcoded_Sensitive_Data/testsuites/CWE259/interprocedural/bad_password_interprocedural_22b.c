/* bad_password_interprocedural_22b.c
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * BAD (sink file): uses the global password set in 22a for authentication.
 * NOTE: This file contains no literal — the smell is in 22a.
 * Our detector produces no finding here (known FN on the sink file).
 * Juliet basis: CWE259_Hard_Coded_Password__w32_char_22b (adapted)
 */
#include <stdio.h>
#include <string.h>

extern char g_password[];

int CWE259_bad_authenticate(const char *input)
{
    /* POTENTIAL FLAW: g_password came from a hardcoded literal in 22a */
    return strcmp(input, g_password) == 0;
}

int main(void)
{
    extern void CWE259_bad_setup(void);
    CWE259_bad_setup();

    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 1;
    buf[strcspn(buf, "\n")] = '\0';

    if (CWE259_bad_authenticate(buf))
        puts("Access granted.");
    else
        puts("Access denied.");
    return 0;
}
