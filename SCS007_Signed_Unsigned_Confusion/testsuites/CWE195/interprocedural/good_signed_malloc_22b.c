/* CWE-195 Signed-to-Unsigned Conversion Error — good: interprocedural sink (flow 22b)
 * Sink  : malloc(data) — data arrived from good_signed_malloc_22a.c
 * FIX   : positivity check in the sink guards the signed-to-unsigned conversion
 */
#include <stdlib.h>
#include <string.h>

void good_signed_malloc_sink(int data)
{
    /* FIX: check data > 0 before using as malloc size */
    if (data > 0 && data < 100)
    {
        char *buf = (char *)malloc(data);
        if (buf == NULL) { return; }
        memset(buf, 'A', data - 1);
        buf[data - 1] = '\0';
        free(buf);
    }
}
