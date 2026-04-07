/* CWE-195 Signed-to-Unsigned Conversion Error — good: malloc size (flow 01)
 * GoodSource: fscanf — signed int read from stdin
 * GoodSink  : positivity check before malloc guards the conversion
 * FIX       : data > 0 check ensures the value is non-negative before use
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void good_malloc_size(void)
{
    int data = -1;
    fscanf(stdin, "%d", &data);

    /* FIX: ensure data is positive before using as malloc size */
    if (data > 0 && data < 100)
    {
        char *buf = (char *)malloc(data);
        if (buf == NULL) { return; }
        memset(buf, 'A', data - 1);
        buf[data - 1] = '\0';
        free(buf);
    }
}
