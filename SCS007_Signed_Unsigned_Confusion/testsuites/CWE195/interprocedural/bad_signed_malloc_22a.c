/* CWE-195 Signed-to-Unsigned Conversion Error — bad: interprocedural source (flow 22a)
 * Source: fscanf reads a signed int into data — may be negative
 * Data is passed unchecked to the sink in bad_signed_malloc_22b.c
 * FLAW  : no positivity check at the call site or in the source function
 */
#include <stdio.h>

/* Sink declared in bad_signed_malloc_22b.c */
void bad_signed_malloc_sink(int data);

void bad_signed_malloc_source(void)
{
    int data = -1;
    /* POTENTIAL FLAW: data may be negative — passed unchecked to sink */
    fscanf(stdin, "%d", &data);
    bad_signed_malloc_sink(data);
}
