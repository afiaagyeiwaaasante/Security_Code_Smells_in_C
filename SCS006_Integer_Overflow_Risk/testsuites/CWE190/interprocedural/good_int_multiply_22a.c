/* CWE-190 Integer Overflow — good: interprocedural multiply, source file (22a)
 * Flow: bad source (rand) passes data to good sink that bounds-checks before multiply.
 * FIX: the sink performs the overflow check — value crosses boundary safely.
 */
#include <stdlib.h>

/* Sink function defined in good_int_multiply_22b.c */
void good_int_multiply_22b_sink(int data);

void good_int_multiply_22a(void)
{
    int data = 0;
    /* Same bad source — rand() value may be large */
    data = rand();
    good_int_multiply_22b_sink(data);
}
