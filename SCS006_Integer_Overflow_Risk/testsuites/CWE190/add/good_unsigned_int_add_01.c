/* CWE-190 Integer Overflow — good: unsigned int addition with boundary check
 * BadSource : max — data initialised to UINT_MAX
 * GoodSink  : guard ensures data < UINT_MAX before adding 1
 * FIX       : wrap-around cannot occur because the bound is checked first
 */
#include <limits.h>

void good_unsigned_int_add(void)
{
    unsigned int data = UINT_MAX;

    /* FIX: check that data + 1 will not wrap */
    if (data < UINT_MAX)
    {
        unsigned int result = data + 1;
        (void)result;
    }
}
