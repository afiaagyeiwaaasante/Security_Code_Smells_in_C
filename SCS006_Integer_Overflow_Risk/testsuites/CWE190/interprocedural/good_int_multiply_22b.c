/* CWE-190 Integer Overflow — good: interprocedural multiply, sink file (22b)
 * Flow: receives data from good_int_multiply_22a; checks before multiplying.
 * FIX: overflow cannot occur because data <= INT_MAX/2 is verified at the sink.
 */
#include <limits.h>

void good_int_multiply_22b_sink(int data)
{
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
