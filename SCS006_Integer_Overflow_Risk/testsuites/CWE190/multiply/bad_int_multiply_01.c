/* CWE-190 Integer Overflow — bad: int multiplication without bounds check
 * BadSource : rand — value may be any positive int
 * BadSink   : data * 2 performed with no overflow guard
 * FLAW      : if data > INT_MAX/2, data * 2 overflows signed int
 */
#include <stdlib.h>

void bad_int_multiply(void)
{
    int data = rand();

    if (data > 0)
    {
        /* POTENTIAL FLAW: if data > INT_MAX/2, data*2 overflows */
        int result = data * 2;
        (void)result;
    }
}
