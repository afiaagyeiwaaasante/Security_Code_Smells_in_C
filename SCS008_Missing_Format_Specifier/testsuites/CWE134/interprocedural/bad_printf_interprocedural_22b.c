/* SCS008 CWE-134 — Missing Format Specifier
 * Group: interprocedural  |  Flow: 22b (sink file)
 * BadSink: printf(data) — data originated in 22a, no literal format here
 * FLAW: user-controlled data used directly as format string across function boundary
 */
#include <stdio.h>

extern char bad_printf_interprocedural_22a_data[100];
extern void bad_printf_interprocedural_22a_source(void);

void bad_printf_interprocedural_22b_sink(void)
{
    char *data = bad_printf_interprocedural_22a_data;
    /* FLAW: variable from another translation unit used as format argument */
    printf(data);
}

int main(void)
{
    bad_printf_interprocedural_22a_source();
    bad_printf_interprocedural_22b_sink();
    return 0;
}
