/* CWE-190 Integer Overflow — good: char addition with bounds check
 * BadSource : fscanf — value read from console, may be CHAR_MAX
 * GoodSink  : guard ensures data < CHAR_MAX before adding 1
 * FIX       : overflow cannot occur because the bound is checked first
 */
#include <stdio.h>
#include <limits.h>

void good_char_add(void)
{
    char data = ' ';
    /* POTENTIAL FLAW: value comes from external input */
    fscanf(stdin, "%c", &data);

    /* FIX: check that data + 1 will not overflow */
    if (data < CHAR_MAX)
    {
        char result = data + 1;
        (void)result;
    }
}
