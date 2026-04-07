/* CWE-190 Integer Overflow — bad: interprocedural multiply, source file (22a)
 * Flow: bad source sets data via rand() in this file;
 *       bad sink in 22b multiplies without bounds check.
 * FLAW: overflow-risky value crosses a function boundary unchecked.
 */
#include <stdlib.h>

/* Sink function defined in bad_int_multiply_22b.c */
void bad_int_multiply_22b_sink(int data);

void bad_int_multiply_22a(void)
{
    int data = 0;
    /* POTENTIAL FLAW: value from rand() may be large */
    data = rand();
    bad_int_multiply_22b_sink(data);
}
