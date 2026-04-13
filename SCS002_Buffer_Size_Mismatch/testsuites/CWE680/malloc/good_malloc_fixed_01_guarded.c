#include "../testsuitesupport/std_testcase.h"
#include <limits.h>
#include <stdint.h>

/* GOOD: fixed data source — explicit overflow guard before malloc.
 * The guard rejects INT_MAX/2+2 before the multiply can wrap.
 * Note: SmellDetect will flag this as a smell (FP) — the guard is not
 *       visible to the srcQL structural pattern. */
void good_malloc_fixed_guarded(void)
{
    int data = INT_MAX / 2 + 2;
    if (data <= 0 || (size_t)data > SIZE_MAX / sizeof(int)) { exit(1); }
    int *p = (int *)malloc((size_t)data * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
