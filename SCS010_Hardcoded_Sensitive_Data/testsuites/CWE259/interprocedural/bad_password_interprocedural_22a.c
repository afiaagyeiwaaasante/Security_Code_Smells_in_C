/* bad_password_interprocedural_22a.c
 * CWE-259 Hardcoded Sensitive Data — SCS010
 * BAD (source file): hardcoded password stored into global variable.
 * The literal is in THIS file — detector will find it here.
 * Juliet basis: CWE259_Hard_Coded_Password__w32_char_22a (adapted)
 */
#include <string.h>

#define PASSWORD "ABCD1234!"

char g_password[64] = "";

void CWE259_bad_setup(void)
{
    /* FLAW: copies a hardcoded literal into the global password */
    strcpy(g_password, PASSWORD);
}
