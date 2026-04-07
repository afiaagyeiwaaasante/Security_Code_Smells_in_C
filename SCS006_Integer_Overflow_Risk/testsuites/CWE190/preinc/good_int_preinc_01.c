/* CWE-190 Integer Overflow — good: pre-increment with bounds check
 * BadSource : rand — value may be INT_MAX
 * GoodSink  : guard ensures data < INT_MAX before incrementing
 * FIX       : overflow cannot occur because the bound is checked first
 */
#include <stdlib.h>
#include <limits.h>

void good_int_preinc(void)
{
    int data = rand();

    /* FIX: check that ++data will not overflow */
    if (data < INT_MAX)
    {
        ++data;
        (void)data;
    }
}
