/* SCS008 CWE-134 — Missing Format Specifier
 * Group: interprocedural  |  Flow: 22b (sink file)  — GOOD variant
 * GoodSink: printf("%s\n", data) — literal format string applied at sink
 * FIX: even though data crosses a function boundary, the sink uses a literal format
 */
#include <stdio.h>

extern char good_printf_interprocedural_22a_data[100];
extern void good_printf_interprocedural_22a_source(void);

void good_printf_interprocedural_22b_sink(void)
{
    char *data = good_printf_interprocedural_22a_data;
    /* FIX: literal format string at the sink */
    printf("%s\n", data);
}

int main(void)
{
    good_printf_interprocedural_22a_source();
    good_printf_interprocedural_22b_sink();
    return 0;
}
