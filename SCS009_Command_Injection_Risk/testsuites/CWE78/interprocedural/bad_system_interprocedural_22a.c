/* bad_system_interprocedural_22a.c
 * CWE-78 Command Injection Risk — SCS009
 * BAD (source file): sets a global char array from fgets().
 * The sink (system()) lives in 22b — interprocedural taint.
 * Juliet basis: CWE78_OS_Command_Injection__char_console_system_22a
 */
#include <stdio.h>
#include <string.h>

#define BUFSIZE 256

char badData[BUFSIZE];

void CWE78_bad_setup(void)
{
    /* Source: console (fgets) — data stored in global for 22b to consume */
    if (fgets(badData, BUFSIZE, stdin) != NULL)
        badData[strcspn(badData, "\n")] = '\0';
}
