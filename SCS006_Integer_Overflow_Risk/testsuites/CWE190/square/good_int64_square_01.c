/* CWE-190 Integer Overflow — good: int64_t squaring with bounds check
 * BadSource : rand — value cast to int64_t
 * GoodSink  : guard checks |data| <= sqrt(INT64_MAX) before squaring
 * FIX       : overflow cannot occur because the bound is checked first
 */
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

void good_int64_square(void)
{
    int64_t data = (int64_t)rand();

    /* FIX: ensure data * data will not overflow int64_t */
    if (llabs(data) <= (int64_t)sqrt((double)INT64_MAX))
    {
        int64_t result = data * data;
        (void)result;
    }
}
