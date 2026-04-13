#include "../testsuitesupport/std_testcase.h"

/* GOOD: size comes from rand() but calloc is used, which performs
 * the count * size overflow check internally.
 * Flow variant: single function, rand data source. */
void good_malloc_rand(void)
{
    int data = rand();
    int *p = (int *)calloc((size_t)data, sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
