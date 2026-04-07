/* CWE-195 Signed-to-Unsigned Conversion Error — bad: malloc size (flow 01)
 * BadSource : fscanf — signed int read from stdin, may be negative
 * BadSink   : malloc(data) — negative data wraps to huge size_t
 * FLAW      : no positivity check before malloc; signed value used as size
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void bad_malloc_size(void)
{
    int data = -1;
    /* POTENTIAL FLAW: data may be negative after user input */
    fscanf(stdin, "%d", &data);

    if (data < 100)
    {
        /* POTENTIAL FLAW: negative data converts to huge size_t — malloc may
         * succeed with a near-SIZE_MAX allocation, enabling heap overflow */
        char *buf = (char *)malloc(data);
        if (buf == NULL) { return; }
        memset(buf, 'A', data - 1);
        buf[data - 1] = '\0';
        free(buf);
    }
}
