/* CWE-190 Integer Overflow — bad: short squaring without bounds check
 * BadSource : rand — value cast to short, may be near SHRT_MAX
 * BadSink   : data * data performed with no overflow guard
 * FLAW      : SHRT_MAX^2 == 1,073,676,289 which overflows short (max 32,767)
 */
#include <stdlib.h>
#include <limits.h>

void bad_short_square(void)
{
    short data = (short)rand();

    /* POTENTIAL FLAW: data * data overflows short when |data| > ~181 */
    short result = data * data;
    (void)result;
}
