#include "../../testsuitesupport/std_testcase.h"

/* BAD: caller — allocates using a size returned from a helper in a separate file.
 * The multiplication happens here, but the tainted value originates in 01b.
 * Flow variant: two-file interprocedural, fixed data source.
 * Expected: MISSED by SmellDetect (single-file srcQL cannot see the callee). */

/* Declared in bad_malloc_interproc_01b.c */
extern int get_tainted_size(void);

void bad_malloc_interproc(void)
{
    int data = get_tainted_size();
    int *p = (int *)malloc(data * sizeof(int));
    if (p == NULL) { exit(1); }
    free(p);
}
