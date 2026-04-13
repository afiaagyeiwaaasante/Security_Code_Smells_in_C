#include "../testsuitesupport/std_testcase.h"

/* BAD: size is read from stdin via fgets then converted with atoi.
 * A user-supplied large value causes (data * sizeof(int)) to overflow.
 * Flow variant: single function, fgets data source.
 * Expected: DETECTED by SmellDetect (malloc($A * $B) in function body). */
void bad_malloc_fgets(void)
{
    char buf[32];
    int data = -1;
    if (fgets(buf, sizeof(buf), stdin) != NULL)
    {
        data = atoi(buf);
    }
    int *p = (int *)malloc(data * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
