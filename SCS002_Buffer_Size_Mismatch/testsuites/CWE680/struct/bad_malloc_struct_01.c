#include "../../testsuitesupport/std_testcase.h"
#include <limits.h>

/* BAD: tainted size is stored in a struct field before being used in malloc.
 * The multiplication appears directly as malloc(ctx.count * sizeof(int)) —
 * srcQL's $A * $B metavariable binds ctx.count to $A and sizeof(int) to $B,
 * so this IS detected by Detector 1 (buffer_size_mismatch).
 * Flow variant: single function, struct-member data source, direct multiply.
 * Expected: FOUND by SmellDetect (direct malloc($A*$B) pattern matches). */
typedef struct { int count; } Context;

void bad_malloc_struct(void)
{
    Context ctx;
    ctx.count = INT_MAX / 2 + 2;
    int *p = (int *)malloc(ctx.count * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
