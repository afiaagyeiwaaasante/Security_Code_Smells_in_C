/* CWE-195 Signed-to-Unsigned Conversion Error — good: strncpy count (flow 01)
 * GoodSource: fscanf — signed int read from stdin
 * GoodSink  : positivity check before strncpy guards the conversion
 * FIX       : data > 0 check ensures the value is non-negative before use
 */
#include <stdio.h>
#include <string.h>

void good_strncpy_count(void)
{
    int data = -1;
    fscanf(stdin, "%d", &data);

    char src[100];
    char dest[100] = "";
    memset(src, 'A', sizeof(src) - 1);
    src[sizeof(src) - 1] = '\0';

    /* FIX: ensure data is positive before using as strncpy count */
    if (data > 0 && data < 100)
    {
        strncpy(dest, src, data);
        dest[data] = '\0';
    }
}
