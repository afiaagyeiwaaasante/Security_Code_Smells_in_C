#include "../testsuitesupport/std_testcase.h"
#include <stdint.h>

/* GOOD: rand data source — explicit overflow guard before malloc.
 * rand() return value is validated before the multiply.
 * Note: SmellDetect will flag this as a smell (FP) — the guard is not
 *       visible to the srcQL structural pattern. */
void good_malloc_rand_guarded(void)
{
    int data = rand();
    if (data <= 0 || (size_t)data > SIZE_MAX / sizeof(int)) { exit(1); }
    int *p = (int *)malloc((size_t)data * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
