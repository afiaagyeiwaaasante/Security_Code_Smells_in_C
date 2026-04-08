/* bad_system_env_01.c
 * CWE-78 Command Injection Risk — SCS009
 * BAD: getenv() reads an environment variable, then system() executes it.
 * Juliet basis: CWE78_OS_Command_Injection__char_environment_system_01
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE 256

int main(void)
{
    char data[BUFSIZE];
    char *env;

    /* Source: environment variable */
    env = getenv("ADD");
    if (env == NULL)
        return 1;

    strncpy(data, env, BUFSIZE - 1);
    data[BUFSIZE - 1] = '\0';

    /* BAD: data flows directly into system() */
    system(data);

    return 0;
}
