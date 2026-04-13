#include "../../testsuitesupport/std_testcase.h"
#include <limits.h>

/* GOOD: size is returned from a helper but calloc is used,
 * which performs the count * size overflow check internally.
 * Flow variant: single-file, size via return value. */

static int get_size(void)
{
    return INT_MAX / 2 + 2;
}

void good_malloc_interproc(void)
{
    int data = get_size();
    int *p = (int *)calloc((size_t)data, sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
