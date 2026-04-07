/* CWE-190 Integer Overflow — good: short squaring with bounds check
 * BadSource : rand — value cast to short
 * GoodSink  : guard checks |data| <= sqrt(SHRT_MAX) before squaring
 * FIX       : overflow cannot occur because the bound is checked first
 */
#include <stdlib.h>
#include <limits.h>
#include <math.h>

void good_short_square(void)
{
    short data = (short)rand();

    /* FIX: ensure data * data will not overflow short */
    if (abs((int)data) <= (int)sqrt((double)SHRT_MAX))
    {
        short result = data * data;
        (void)result;
    }
}
