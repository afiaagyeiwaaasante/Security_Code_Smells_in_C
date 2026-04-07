/* CWE-190 Integer Overflow — bad: interprocedural multiply, sink file (22b)
 * Flow: receives data from bad_int_multiply_22a; multiplies without check.
 * FLAW: no bounds check before data * 2 — may overflow if data > INT_MAX/2.
 */
#include <limits.h>

void bad_int_multiply_22b_sink(int data)
{
    if (data > 0)
    {
        /* POTENTIAL FLAW: data * 2 overflows when data > INT_MAX/2 */
        int result = data * 2;
        (void)result;
    }
}
