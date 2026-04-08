/* bad_popen_console_01.c
 * CWE-78 Command Injection Risk — SCS009
 * BAD: fgets() reads user input, then popen() opens a pipe using that data.
 * Juliet basis: CWE78_OS_Command_Injection__char_console_popen_01
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(void)
{
    char data[BUFSIZE];
    FILE *pipe;

    /* Source: console (fgets) */
    if (fgets(data, BUFSIZE, stdin) == NULL)
        return 1;

    /* Remove trailing newline */
    data[strcspn(data, "\n")] = '\0';

    /* BAD: data flows directly into popen() */
    pipe = popen(data, "r");
    if (pipe != NULL)
        pclose(pipe);

    return 0;
}
