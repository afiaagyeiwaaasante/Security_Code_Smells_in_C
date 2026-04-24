#include "../../testsuitesupport/std_testcase.h"
#include <limits.h>

/* BAD: size is precomputed into a struct field (not a local variable), then
 * passed to malloc. This is the genuine double limitation:
 *   - Detector 1 (buffer_size_mismatch): sees malloc(ctx.sz) — no * in the
 *     malloc argument, so the $A * $B pattern does not match.
 *   - Detector 2 (precomputed_size): pattern is $TYPE $SZ = $A * $B FOLLOWED
 *     BY malloc($SZ). The assignment ctx.sz = ... is an expression statement,
 *     not a variable declaration, so $TYPE $SZ = ... does not bind.
 * Flow variant: single function, size stored in struct field via assignment.
 * Expected: MISSED by SmellDetect (struct field assignment breaks both detectors). */
typedef struct { int count; size_t sz; } Context;

void bad_malloc_struct_precomp(void)
{
    Context ctx;
    ctx.count = INT_MAX / 2 + 2;
    ctx.sz = (size_t)ctx.count * sizeof(int);   /* stored in struct field, not local */
    int *p = (int *)malloc(ctx.sz);             /* no * visible in malloc argument */
    if (p == NULL) { exit(1); }
    free(p);
}
