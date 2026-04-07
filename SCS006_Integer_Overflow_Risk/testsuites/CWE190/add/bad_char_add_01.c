/* CWE-190 Integer Overflow — bad: char addition without bounds check
 * BadSource : fscanf — value read from console, may be CHAR_MAX
 * BadSink   : data + 1 performed with no overflow guard
 * FLAW      : if data == CHAR_MAX, data + 1 wraps to CHAR_MIN
 */
#include <stdio.h>
#include <limits.h>

void bad_char_add(void)
{
    char data = ' ';
    /* POTENTIAL FLAW: value comes from external input */
    fscanf(stdin, "%c", &data);

    /* POTENTIAL FLAW: no check — data + 1 overflows when data == CHAR_MAX */
    char result = data + 1;
    (void)result;
}
