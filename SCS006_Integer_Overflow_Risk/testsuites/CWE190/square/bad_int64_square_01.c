/* CWE-190 Integer Overflow — bad: int64_t squaring without bounds check
 * BadSource : rand — value cast to int64_t, may be large
 * BadSink   : data * data performed with no overflow guard
 * FLAW      : wide type does not prevent overflow — data * data can exceed INT64_MAX
 */
#include <stdlib.h>
#include <stdint.h>

void bad_int64_square(void)
{
    int64_t data = (int64_t)rand();

    /* POTENTIAL FLAW: data * data overflows when data > sqrt(INT64_MAX) (~3e9) */
    int64_t result = data * data;
    (void)result;
}
