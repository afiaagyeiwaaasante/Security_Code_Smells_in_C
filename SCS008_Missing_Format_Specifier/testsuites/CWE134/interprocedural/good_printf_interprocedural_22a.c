/* SCS008 CWE-134 — Missing Format Specifier
 * Group: interprocedural  |  Flow: 22a (source file)  — GOOD variant
 * Same source as bad; fix applied in 22b.
 */
#include <stdio.h>
#include <string.h>

char good_printf_interprocedural_22a_data[100];

void good_printf_interprocedural_22a_source(void)
{
    char *data = good_printf_interprocedural_22a_data;
    data[0] = '\0';
    if (fgets(data, 100, stdin) != NULL) {
        size_t len = strlen(data);
        if (len > 0 && data[len - 1] == '\n') data[len - 1] = '\0';
    }
}
