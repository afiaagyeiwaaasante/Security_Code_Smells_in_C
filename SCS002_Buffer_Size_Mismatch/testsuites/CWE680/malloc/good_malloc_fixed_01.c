#include "../testsuitesupport/std_testcase.h"
#include <limits.h>

/* GOOD: calloc(count, size) performs the overflow check internally
 * and returns NULL if count * size would overflow SIZE_MAX.
 * Flow variant: single function, fixed data source. */
void good_malloc_fixed(void)
{
    int data = INT_MAX / 2 + 2;
    int *p = (int *)calloc((size_t)data, sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
