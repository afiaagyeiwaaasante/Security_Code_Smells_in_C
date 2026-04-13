#include "../testsuitesupport/std_testcase.h"

/* BAD: size is produced by rand(), which can return a value large enough
 * that (data * sizeof(int)) overflows SIZE_MAX.
 * Flow variant: single function, rand data source.
 * Expected: DETECTED by SmellDetect (malloc($A * $B) in function body). */
void bad_malloc_rand(void)
{
    int data = rand();
    int *p = (int *)malloc(data * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
