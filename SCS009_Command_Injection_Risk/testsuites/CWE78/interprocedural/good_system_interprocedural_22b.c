/* good_system_interprocedural_22b.c
 * CWE-78 Command Injection Risk — SCS009
 * GOOD: system() is called with a hard-coded string literal.
 * Juliet basis: CWE78_OS_Command_Injection__char_console_system_22b (goodG2B)
 */
#include <stdlib.h>

void CWE78_good_sink(void)
{
    /* GOOD: system() receives a fixed literal — no taint */
    system("ls -l");
}

int main(void)
{
    CWE78_good_sink();
    return 0;
}
