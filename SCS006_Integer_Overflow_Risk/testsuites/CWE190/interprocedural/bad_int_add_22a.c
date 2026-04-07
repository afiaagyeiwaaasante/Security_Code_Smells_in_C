/* CWE-190 Integer Overflow — bad: interprocedural add, source file (22a)
 * Flow: bad source reads data via fscanf; bad sink in 22b adds without check.
 * FLAW: user-controlled value crosses a function boundary unchecked.
 */
#include <stdio.h>

/* Sink function defined in bad_int_add_22b.c */
void bad_int_add_22b_sink(int data);

void bad_int_add_22a(void)
{
    int data = 0;
    /* POTENTIAL FLAW: value from console — may be INT_MAX */
    fscanf(stdin, "%d", &data);
    bad_int_add_22b_sink(data);
}
