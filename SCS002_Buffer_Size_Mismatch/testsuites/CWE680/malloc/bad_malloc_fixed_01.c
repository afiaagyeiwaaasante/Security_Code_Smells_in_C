#include "../testsuitesupport/std_testcase.h"
#include <limits.h>

/* BAD: data is a fixed compile-time constant that overflows when multiplied.
 * INT_MAX/2 + 2 causes (data * sizeof(int)) to wrap to a tiny value,
 * so malloc allocates far less memory than the loop then accesses.
 * Flow variant: single function, fixed data source.
 * Expected: DETECTED by SmellDetect (malloc($A * $B) in function body). */
void bad_malloc_fixed(void)
{
    int data = INT_MAX / 2 + 2;
    int *p = (int *)malloc(data * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
