#include "../../testsuitesupport/std_testcase.h"
#include <limits.h>

/* GOOD: same struct-member pattern but calloc is used instead of malloc,
 * so the overflow is handled internally.
 * Flow variant: single function, struct-member data source. */
typedef struct { int count; } Context;

void good_malloc_struct(void)
{
    Context ctx;
    ctx.count = INT_MAX / 2 + 2;
    int *p = (int *)calloc((size_t)ctx.count, sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
