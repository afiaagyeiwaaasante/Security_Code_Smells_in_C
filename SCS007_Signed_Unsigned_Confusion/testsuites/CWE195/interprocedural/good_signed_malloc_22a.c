/* CWE-195 Signed-to-Unsigned Conversion Error — good: interprocedural source (flow 22a)
 * Source: fscanf reads a signed int into data
 * Data is passed to the sink in good_signed_malloc_22b.c
 * FIX   : sink guards with data > 0 before calling malloc
 */
#include <stdio.h>

/* Sink declared in good_signed_malloc_22b.c */
void good_signed_malloc_sink(int data);

void good_signed_malloc_source(void)
{
    int data = -1;
    fscanf(stdin, "%d", &data);
    good_signed_malloc_sink(data);
}
