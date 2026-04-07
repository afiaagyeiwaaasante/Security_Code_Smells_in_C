/* CWE-195 Signed-to-Unsigned Conversion Error — bad: interprocedural sink (flow 22b)
 * Sink  : malloc(data) — data arrived from bad_signed_malloc_22a.c
 * FLAW  : sink performs no positivity check; negative data wraps to huge size_t
 */
#include <stdlib.h>
#include <string.h>

void bad_signed_malloc_sink(int data)
{
    if (data < 100)
    {
        /* POTENTIAL FLAW: data may be negative from caller — wraps to huge size_t */
        char *buf = (char *)malloc(data);
        if (buf == NULL) { return; }
        memset(buf, 'A', data - 1);
        buf[data - 1] = '\0';
        free(buf);
    }
}
