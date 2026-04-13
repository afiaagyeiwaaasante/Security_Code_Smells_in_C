#include "../testsuitesupport/std_testcase.h"

/* BAD: multiplication stored in an intermediate variable before malloc.
 * The overflow happens at the assignment, not inside malloc() itself.
 * The existing detector misses this because malloc(sz) has no * in its argument.
 * Flow variant: single function, precomputed size.
 * Expected: DETECTED by detect_precomputed_size detector. */
void bad_malloc_precomputed(int n)
{
    size_t sz = n * sizeof(int);   /* overflow risk here */
    int *p = (int *)malloc(sz);    /* no * visible to the basic detector */
    if (p == NULL) { exit(1); }
    free(p);
}
