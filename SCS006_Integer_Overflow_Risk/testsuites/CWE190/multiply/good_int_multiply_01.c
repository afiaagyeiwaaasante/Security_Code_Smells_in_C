/* CWE-190 Integer Overflow — good: int multiplication with bounds check
 * BadSource : rand — value may be any positive int
 * GoodSink  : guard ensures data <= INT_MAX/2 before multiplying
 * FIX       : overflow cannot occur because the bound is checked first
 */
#include <stdlib.h>
#include <limits.h>

void good_int_multiply(void)
{
    int data = rand();

    if (data > 0)
    {
        /* FIX: check that data * 2 will not overflow */
        if (data <= (INT_MAX / 2))
        {
            int result = data * 2;
            (void)result;
        }
    }
}
