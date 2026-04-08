/* bad_system_console_01.c
 * CWE-78 Command Injection Risk — SCS009
 * BAD: fgets() reads user input, then system() executes it without sanitisation.
 * Juliet basis: CWE78_OS_Command_Injection__char_console_system_01
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(void)
{
    char data[BUFSIZE];

    /* Source: console (fgets) */
    if (fgets(data, BUFSIZE, stdin) == NULL)
        return 1;

    /* Remove trailing newline */
    data[strcspn(data, "\n")] = '\0';

    /* BAD: data flows directly into system() */
    system(data);

    return 0;
}
