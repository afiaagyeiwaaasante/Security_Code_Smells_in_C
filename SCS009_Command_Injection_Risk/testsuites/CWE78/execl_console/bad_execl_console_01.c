/* bad_execl_console_01.c
 * CWE-78 Command Injection Risk — SCS009
 * BAD: fgets() reads user input into a path, then execl() executes it.
 * Juliet basis: CWE78_OS_Command_Injection__char_console_execl variant
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 256

int main(void)
{
    char data[BUFSIZE];

    /* Source: console (fgets) */
    if (fgets(data, BUFSIZE, stdin) == NULL)
        return 1;

    data[strcspn(data, "\n")] = '\0';

    /* BAD: data flows directly into execl() as the executable path */
    execl(data, data, (char *)NULL);

    return 0;
}
