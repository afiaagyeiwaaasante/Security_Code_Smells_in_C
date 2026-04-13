#include "../../testsuitesupport/std_testcase.h"
#include <limits.h>

/* BAD: tainted size is stored in a struct field before being used in malloc.
 * The multiplication appears as (ctx.count * sizeof(int)) — the variable is
 * a struct member, not a plain local, so srcQL's $A * $B metavariable binding
 * does not match it.
 * Flow variant: single function, struct-member data source.
 * Expected: MISSED by SmellDetect (struct field access breaks pattern match). */
typedef struct { int count; } Context;

void bad_malloc_struct(void)
{
    Context ctx;
    ctx.count = INT_MAX / 2 + 2;
    int *p = (int *)malloc(ctx.count * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
