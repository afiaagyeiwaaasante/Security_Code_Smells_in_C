/* good_system_console_01.c
 * CWE-78 Command Injection Risk — SCS009
 * GOOD: system() is called with a hard-coded string literal — no user input.
 * Juliet basis: CWE78_OS_Command_Injection__char_console_system_01 (goodG2B)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(void)
{
    char data[BUFSIZE];

    /* Source: console (fgets) — data is read but not used in system() */
    if (fgets(data, BUFSIZE, stdin) == NULL)
        return 1;

    /* GOOD: system() receives a fixed literal, not user-supplied data */
    system("ls -l");

    return 0;
}
