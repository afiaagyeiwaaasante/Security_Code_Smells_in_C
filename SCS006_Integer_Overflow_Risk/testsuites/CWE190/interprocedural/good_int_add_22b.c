/* CWE-190 Integer Overflow — good: interprocedural add, sink file (22b)
 * Flow: receives data from good_int_add_22a; checks before adding 1.
 * FIX: overflow cannot occur because data < INT_MAX is verified at the sink.
 */
#include <limits.h>

void good_int_add_22b_sink(int data)
{
    /* FIX: check that data + 1 will not overflow */
    if (data < INT_MAX)
    {
        int result = data + 1;
        (void)result;
    }
}
