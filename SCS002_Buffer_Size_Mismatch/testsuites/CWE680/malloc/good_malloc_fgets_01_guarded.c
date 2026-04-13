#include "../testsuitesupport/std_testcase.h"
#include <stdint.h>

/* GOOD: fgets data source — explicit overflow guard before malloc.
 * User-supplied value from stdin is validated before the multiply.
 * Note: SmellDetect will flag this as a smell (FP) — the guard is not
 *       visible to the srcQL structural pattern. */
void good_malloc_fgets_guarded(void)
{
    char buf[32];
    int data = -1;
    if (fgets(buf, sizeof(buf), stdin) != NULL)
    {
        data = atoi(buf);
    }
    if (data <= 0 || (size_t)data > SIZE_MAX / sizeof(int)) { exit(1); }
    int *p = (int *)malloc((size_t)data * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
