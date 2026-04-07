/* CWE-195 Signed-to-Unsigned Conversion Error — bad: memcpy count (flow 01)
 * BadSource : fscanf — signed int read from stdin, may be negative
 * BadSink   : memcpy(dest, src, data) — negative data wraps to huge size_t
 * FLAW      : no positivity check before memcpy; signed value used as count
 *
 * Note: memmove() with a signed count exhibits the same flaw and is covered
 *       by this group — detection pattern is identical.
 */
#include <stdio.h>
#include <string.h>

void bad_memcpy_count(void)
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
         * memcpy reads far beyond src, causing memory disclosure or crash */
        memcpy(dest, src, data);
        dest[data] = '\0';
    }
}
