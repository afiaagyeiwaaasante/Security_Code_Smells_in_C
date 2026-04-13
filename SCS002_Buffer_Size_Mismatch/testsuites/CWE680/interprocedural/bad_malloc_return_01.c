#include "../../testsuitesupport/std_testcase.h"
#include <limits.h>

/* BAD: size is returned from a helper function within the same file.
 * The multiply happens at the call site, but the tainted value travels
 * through a function return — the srcQL FOLLOWED BY chain does not cross
 * function boundaries in a single-file query.
 * Flow variant: single-file, size via return value.
 * Expected: MISSED by SmellDetect (srcQL sees the malloc but cannot trace
 *           that get_size() returns a dangerous value). */

static int get_size(void)
{
    return INT_MAX / 2 + 2;
}

void bad_malloc_return(void)
{
    int data = get_size();
    int *p = (int *)malloc(data * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
