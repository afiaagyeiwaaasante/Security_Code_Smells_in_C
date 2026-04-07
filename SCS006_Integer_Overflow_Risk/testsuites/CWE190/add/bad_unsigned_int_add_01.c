/* CWE-190 Integer Overflow — bad: unsigned int addition at boundary
 * BadSource : max — data initialised to UINT_MAX
 * BadSink   : data + 1 performed with no overflow guard
 * FLAW      : unsigned wrap-around — UINT_MAX + 1 == 0 (defined but wrong)
 */
#include <limits.h>

void bad_unsigned_int_add(void)
{
    unsigned int data = UINT_MAX;

    /* POTENTIAL FLAW: no check — UINT_MAX + 1 wraps to 0 */
    unsigned int result = data + 1;
    (void)result;
}
