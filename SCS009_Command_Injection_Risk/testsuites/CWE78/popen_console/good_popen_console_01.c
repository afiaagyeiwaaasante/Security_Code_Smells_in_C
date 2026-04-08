/* good_popen_console_01.c
 * CWE-78 Command Injection Risk — SCS009
 * GOOD: popen() is called with a hard-coded string literal — no user input.
 * Juliet basis: CWE78_OS_Command_Injection__char_console_popen_01 (goodG2B)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(void)
{
    char data[BUFSIZE];
    FILE *pipe;

    /* Source: console (fgets) — data is read but not forwarded to popen() */
    if (fgets(data, BUFSIZE, stdin) == NULL)
        return 1;

    /* GOOD: popen() receives a fixed literal */
    pipe = popen("ls -l", "r");
    if (pipe != NULL)
        pclose(pipe);

    return 0;
}
