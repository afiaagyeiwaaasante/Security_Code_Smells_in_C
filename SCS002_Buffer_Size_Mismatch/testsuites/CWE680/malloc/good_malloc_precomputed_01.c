#include "../testsuitesupport/std_testcase.h"
#include <stdint.h>

/* GOOD: guard before the precomputed size assignment prevents overflow.
 * The SIZE_MAX check ensures sz cannot wrap before malloc receives it. */
void good_malloc_precomputed(int n)
{
    if (n <= 0 || (size_t)n > SIZE_MAX / sizeof(int)) { exit(1); }
    size_t sz = (size_t)n * sizeof(int);
    int *p = (int *)malloc(sz);
    if (p == NULL) { exit(1); }
    free(p);
}
