/* SCS008 CWE-134 — Missing Format Specifier
 * Group: printf_direct  |  Flow: 01 Baseline
 * BadSource: console (fgets)
 * BadSink  : printf(data) — no format string literal
 * FLAW: user-controlled string passed directly as printf format argument
 */
#include <stdio.h>
#include <string.h>

void bad_printf_direct_01(void)
{
    char data[100] = "";
    if (fgets(data, sizeof(data), stdin) != NULL) {
        size_t len = strlen(data);
        if (len > 0 && data[len - 1] == '\n') data[len - 1] = '\0';
    }
    /* FLAW: variable used directly as format argument */
    printf(data);
}

int main(void) { bad_printf_direct_01(); return 0; }
