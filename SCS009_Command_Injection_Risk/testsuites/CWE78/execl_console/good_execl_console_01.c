/* good_execl_console_01.c
 * CWE-78 Command Injection Risk — SCS009
 * GOOD: execl() called with a hardcoded literal path — no user input.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    /* FIX: hardcoded path — not user-controlled */
    execl("/bin/ls", "ls", "-l", (char *)NULL);

    return 0;
}
