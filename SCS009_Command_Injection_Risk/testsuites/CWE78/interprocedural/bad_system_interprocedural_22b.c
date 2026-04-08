/* bad_system_interprocedural_22b.c
 * CWE-78 Command Injection Risk — SCS009
 * BAD (sink file): calls system() with the tainted global from 22a.
 * NOTE: Our detector sees system() here but no fgets/getenv in this block,
 *       so this is a KNOWN FALSE NEGATIVE (interprocedural flow).
 * Juliet basis: CWE78_OS_Command_Injection__char_console_system_22b
 */
#include <stdlib.h>

extern char badData[];

void CWE78_bad_sink(void)
{
    /* BAD: data from 22a — tainted via global, no source visible in this file */
    system(badData);
}

int main(void)
{
    extern void CWE78_bad_setup(void);
    CWE78_bad_setup();
    CWE78_bad_sink();
    return 0;
}
