/* SCS008 CWE-134 — Missing Format Specifier
 * Group: env_format  |  Flow: 01 Baseline
 * BadSource: getenv() — environment variable
 * GoodSink : printf("%s\n", data) — literal format string
 * FIX: data is passed as a value argument, not the format argument
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void good_env_format_01(void)
{
    char data[100] = "";
    char *env = getenv("ADD");
    if (env != NULL)
        strncpy(data, env, sizeof(data) - 1);
    /* FIX: literal format string — env value cannot inject directives */
    printf("%s\n", data);
}

int main(void) { good_env_format_01(); return 0; }
