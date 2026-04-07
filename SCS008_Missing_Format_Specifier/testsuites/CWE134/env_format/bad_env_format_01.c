/* SCS008 CWE-134 — Missing Format Specifier
 * Group: env_format  |  Flow: 01 Baseline
 * BadSource: getenv() — environment variable
 * BadSink  : printf(data) — env value used directly as format
 * FLAW: attacker-controlled env variable injected as printf format string
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void bad_env_format_01(void)
{
    char data[100] = "";
    char *env = getenv("ADD");
    if (env != NULL)
        strncpy(data, env, sizeof(data) - 1);
    /* FLAW: env-derived value used directly as format argument */
    printf(data);
}

int main(void) { bad_env_format_01(); return 0; }
