/* good_system_env_01.c
 * CWE-78 Command Injection Risk — SCS009
 * GOOD: system() is called with a hard-coded string literal — no env input used.
 * Juliet basis: CWE78_OS_Command_Injection__char_environment_system_01 (goodG2B)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(void)
{
    char data[BUFSIZE];
    char *env;

    /* Source: environment variable — read but not forwarded to system() */
    env = getenv("ADD");
    if (env == NULL)
        return 1;

    strncpy(data, env, BUFSIZE - 1);
    data[BUFSIZE - 1] = '\0';

    /* GOOD: system() receives a fixed literal */
    system("ls -l");

    return 0;
}
