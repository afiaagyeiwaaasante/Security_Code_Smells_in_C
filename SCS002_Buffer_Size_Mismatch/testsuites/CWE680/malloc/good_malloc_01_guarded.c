#include "../testsuitesupport/std_testcase.h"
#include <stdint.h>

/* GOOD: explicit overflow guard before malloc.
 * If n > SIZE_MAX / sizeof(int), the multiplication would wrap — reject it.
 * The malloc(n * sizeof(int)) pattern is present but safe because the guard
 * makes it unreachable with an overflowing value.
 * Flow variant: single function, generic input.
 * Note: SmellDetect will flag this as a smell (FP) — the guard is not
 *       visible to the srcQL structural pattern. */
void good_malloc_guarded(int n)
{
    if (n <= 0 || (size_t)n > SIZE_MAX / sizeof(int)) { exit(1); }
    int *p = (int *)malloc((size_t)n * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
