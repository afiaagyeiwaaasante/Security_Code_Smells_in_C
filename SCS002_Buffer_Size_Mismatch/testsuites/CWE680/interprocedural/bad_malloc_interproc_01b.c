#include "../../testsuitesupport/std_testcase.h"
#include <limits.h>

/* BAD: callee — returns a fixed value that will overflow when multiplied
 * by sizeof(int) in the caller (01a).
 * Flow variant: two-file interprocedural, fixed data source. */
int get_tainted_size(void)
{
    return INT_MAX / 2 + 2;
}
