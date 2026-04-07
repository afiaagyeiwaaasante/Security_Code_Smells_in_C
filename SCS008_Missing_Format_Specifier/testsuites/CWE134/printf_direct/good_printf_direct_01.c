/* SCS008 CWE-134 — Missing Format Specifier
 * Group: printf_direct  |  Flow: 01 Baseline
 * BadSource: console (fgets)
 * GoodSink : printf("%s\n", data) — literal format string
 * FIX: use a literal format specifier so data is treated as a value, not a format
 */
#include <stdio.h>
#include <string.h>

void good_printf_direct_01(void)
{
    char data[100] = "";
    if (fgets(data, sizeof(data), stdin) != NULL) {
        size_t len = strlen(data);
        if (len > 0 && data[len - 1] == '\n') data[len - 1] = '\0';
    }
    /* FIX: literal format string — data cannot inject format directives */
    printf("%s\n", data);
}

int main(void) { good_printf_direct_01(); return 0; }
