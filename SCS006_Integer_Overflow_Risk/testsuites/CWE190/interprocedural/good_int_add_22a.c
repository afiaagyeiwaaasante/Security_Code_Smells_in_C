/* CWE-190 Integer Overflow — good: interprocedural add, source file (22a)
 * Flow: bad source (fscanf) passes data to good sink that bounds-checks before add.
 * FIX: the sink performs the overflow check — value crosses boundary safely.
 */
#include <stdio.h>

/* Sink function defined in good_int_add_22b.c */
void good_int_add_22b_sink(int data);

void good_int_add_22a(void)
{
    int data = 0;
    /* Same bad source — value from console may be INT_MAX */
    fscanf(stdin, "%d", &data);
    good_int_add_22b_sink(data);
}
