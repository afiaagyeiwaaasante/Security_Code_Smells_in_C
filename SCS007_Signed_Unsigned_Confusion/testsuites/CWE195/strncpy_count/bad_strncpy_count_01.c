/* CWE-195 Signed-to-Unsigned Conversion Error — bad: strncpy count (flow 01)
 * BadSource : fscanf — signed int read from stdin, may be negative
 * BadSink   : strncpy(dest, src, data) — negative data wraps to huge size_t
 * FLAW      : no positivity check before strncpy; signed value used as count
 */
#include <stdio.h>
#include <string.h>

void bad_strncpy_count(void)
{
    int data = -1;
    /* POTENTIAL FLAW: data may be negative after user input */
    fscanf(stdin, "%d", &data);

    char src[100];
    char dest[100] = "";
    memset(src, 'A', sizeof(src) - 1);
    src[sizeof(src) - 1] = '\0';

    if (data < 100)
    {
        /* POTENTIAL FLAW: negative data converts to huge size_t —
         * strncpy becomes an unbounded copy, enabling buffer overflow */
        strncpy(dest, src, data);
        dest[data] = '\0';
    }
}
