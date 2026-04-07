/* SCS008 CWE-134 — Missing Format Specifier
 * Group: interprocedural  |  Flow: 22a (source file)
 * BadSource: static global populated by 22a, consumed by 22b
 * Data flows from this file into bad_printf_interprocedural_22b.c
 */
#include <stdio.h>
#include <string.h>

char bad_printf_interprocedural_22a_data[100];

void bad_printf_interprocedural_22a_source(void)
{
    char *data = bad_printf_interprocedural_22a_data;
    data[0] = '\0';
    /* FLAW: read user input into shared buffer — no format guard at source */
    if (fgets(data, 100, stdin) != NULL) {
        size_t len = strlen(data);
        if (len > 0 && data[len - 1] == '\n') data[len - 1] = '\0';
    }
}
