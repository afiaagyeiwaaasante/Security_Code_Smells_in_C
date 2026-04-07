/* CWE-190 Integer Overflow — bad: post-increment without bounds check
 * BadSource : rand — value may be INT_MAX
 * BadSink   : data++ performed with no overflow guard
 * FLAW      : if data == INT_MAX, data++ wraps to INT_MIN (undefined behaviour)
 */
#include <stdlib.h>

void bad_int_postinc(void)
{
    int data = rand();

    /* POTENTIAL FLAW: data++ overflows when data == INT_MAX */
    data++;
    (void)data;
}
