#include "../../testsuitesupport/std_testcase.h"
#include <limits.h>

/* GOOD: same struct-field precomputed pattern but uses calloc, which
 * performs the overflow check internally — no integer overflow risk.
 * Flow variant: single function, size stored in struct field via assignment.
 * Expected: CLEAN (no finding). */
typedef struct { int count; size_t sz; } Context;

void good_malloc_struct_precomp(void)
{
    Context ctx;
    ctx.count = 10;
    ctx.sz = (size_t)ctx.count * sizeof(int);
    int *p = (int *)calloc((size_t)ctx.count, sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
